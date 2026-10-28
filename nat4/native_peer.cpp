#include <rtc/rtc.h>
#include <nlohmann/json.hpp>
#include <array>
#include <atomic>
#include <chrono>
#include <iostream>
#include <mutex>
#include <set>
#include <thread>

using json = nlohmann::json;
std::mutex outputMutex, statsMutex;
std::atomic<int> input{-1}, control{-1};
std::set<unsigned> received[2], echoed[2];
unsigned errors = 0, orderErrors = 0;
unsigned origin = 0, packetCount = 300, idleSeconds = 0;
std::atomic<bool> running{true};

void emit(const json &value) {
    std::lock_guard lock(outputMutex);
    std::cout << value.dump() << std::endl;
}

void check(int result, const char *operation) {
    if (result < 0) throw std::runtime_error(std::string(operation) + ": " + std::to_string(result));
}

void onMessage(int id, const char *data, int size, void *) {
    std::lock_guard lock(statsMutex);
    if (size != 96) { ++errors; return; }
    auto p = reinterpret_cast<const unsigned char *>(data);
    int lane = id == control ? 1 : 0;
    unsigned seq = p[4] | (unsigned(p[5]) << 8) | (unsigned(p[6]) << 16) | (unsigned(p[7]) << 24);
    if (p[0] != (lane ? 67 : 84) || p[1] > 1 || p[2] > 1 || p[3] != 0 ||
        seq >= (lane ? packetCount / 10 : packetCount)) { ++errors; return; }
    for (int i = 8; i < size; ++i) if (p[i] != (seq + i) % 251) { ++errors; return; }
    if (p[1] != origin && p[2] == 0) {
        if (lane && !received[lane].count(seq) && seq != received[lane].size()) ++orderErrors;
        received[lane].insert(seq);
        std::array<char, 96> copy;
        std::copy(data, data + size, copy.begin());
        copy[2] = 1;
        if (rtcSendMessage(id, copy.data(), size) < 0) ++errors;
    } else if (p[1] == origin && p[2] == 1) {
        echoed[lane].insert(seq);
    } else ++errors;
}

void attach(int id) {
    char label[128]{};
    check(rtcGetDataChannelLabel(id, label, sizeof(label)), "label");
    if (std::string(label) == "th07-input") input = id;
    else if (std::string(label) == "th07-control") control = id;
    else throw std::runtime_error("unexpected channel label");
    rtcSetMessageCallback(id, onMessage);
    rtcSetOpenCallback(id, [](int dc, void *) {
        rtcReliability r{};
        rtcGetDataChannelReliability(dc, &r);
        emit({{"type", "open"}, {"lane", dc == input ? "input" : "control"},
              {"unordered", r.unordered}, {"unreliable", r.unreliable}, {"maxRetransmits", r.maxRetransmits}});
    });
}

int main(int argc, char **argv) {
    int pc = -1;
    std::thread sender;
    try {
        if (argc > 2) origin = std::stoul(argv[2]);
        if (argc > 3) packetCount = std::stoul(argv[3]);
        if (argc > 4) idleSeconds = std::stoul(argv[4]);
        unsigned localPort = argc > 5 ? std::stoul(argv[5]) : 0;
        if (origin > 1 || packetCount < 300 || packetCount > 3600 || packetCount % 20 || idleSeconds > 30)
            throw std::runtime_error("invalid origin, packet count or idle interval");
        if (localPort && (localPort < 1024 || localPort > 65535))
            throw std::runtime_error("invalid pre-punched local port");
        rtcInitLogger(RTC_LOG_WARNING, [](rtcLogLevel, const char *message) { std::cerr << message << '\n'; });
        rtcSetThreadPoolSize(2);
        const char *servers[] = {argc > 6 ? argv[6] : "stun:198.18.0.10:3478"};
        rtcConfiguration cfg{};
        cfg.iceServers = servers;
        cfg.iceServersCount = localPort && argc <= 6 ? 0 : 1;
        cfg.portRangeBegin = cfg.portRangeEnd = localPort;
        cfg.disableAutoNegotiation = true;
        cfg.mtu = 1200;
        cfg.maxMessageSize = 65536;
        pc = rtcCreatePeerConnection(&cfg);
        check(pc, "create");
        rtcSetLocalDescriptionCallback(pc, [](int, const char *sdp, const char *type, void *) {
            emit({{"type", "description"}, {"description", {{"type", type}, {"sdp", sdp}}}});
        });
        rtcSetLocalCandidateCallback(pc, [](int, const char *candidate, const char *mid, void *) {
            emit({{"type", "candidate"}, {"candidate", {{"candidate", candidate}, {"sdpMid", mid}}}});
        });
        rtcSetStateChangeCallback(pc, [](int, rtcState state, void *) { emit({{"type", "state"}, {"state", int(state)}}); });
        rtcSetDataChannelCallback(pc, [](int, int dc, void *) { attach(dc); });
        if (argc > 1 && std::string(argv[1]) == "offer") {
            attach(rtcCreateDataChannel(pc, "th07-control"));
            rtcDataChannelInit init{};
            init.reliability.unordered = true;
            init.reliability.unreliable = true;
            init.reliability.maxRetransmits = 0;
            attach(rtcCreateDataChannelEx(pc, "th07-input", &init));
            check(rtcSetLocalDescription(pc, "offer"), "offer");
        }
        emit({{"type", "ready"}, {"origin", origin}, {"packets", packetCount}});
        std::string line;
        while (std::getline(std::cin, line)) {
            auto message = json::parse(line);
            auto type = message.at("type").get<std::string>();
            if (type == "description") {
                const auto &d = message.at("description");
                auto sdp = d.at("sdp").get<std::string>(), kind = d.at("type").get<std::string>();
                check(rtcSetRemoteDescription(pc, sdp.c_str(), kind.c_str()), "remote description");
                if (kind == "offer") check(rtcSetLocalDescription(pc, "answer"), "answer");
            } else if (type == "candidate") {
                const auto &c = message.at("candidate");
                auto candidate = c.at("candidate").get<std::string>(), mid = c.value("sdpMid", "0");
                check(rtcAddRemoteCandidate(pc, candidate.c_str(), mid.c_str()), "remote candidate");
            } else if (type == "start") {
                if (sender.joinable() || input < 0 || control < 0 || !rtcIsOpen(input) || !rtcIsOpen(control))
                    throw std::runtime_error("start requires both open channels, once");
                sender = std::thread([] {
                    for (unsigned n = 0; n < packetCount && running; ++n) {
                        if (n == packetCount / 2 && idleSeconds) {
                            emit({{"type", "idle"}, {"seconds", idleSeconds}});
                            auto until = std::chrono::steady_clock::now() + std::chrono::seconds(idleSeconds);
                            while (running && std::chrono::steady_clock::now() < until)
                                std::this_thread::sleep_for(std::chrono::milliseconds(16));
                            if (!running) break;
                            emit({{"type", "resumed"}});
                        }
                        for (unsigned lane = 0; lane < 2; ++lane) {
                            if (lane && n % 10) continue;
                            unsigned seq = lane ? n / 10 : n;
                            std::array<char, 96> data{};
                            data[0] = lane ? 67 : 84;
                            data[1] = origin;
                            for (int i = 0; i < 4; ++i) data[4 + i] = (seq >> (8 * i)) & 255;
                            for (int i = 8; i < 96; ++i) data[i] = (seq + i) % 251;
                            if (rtcSendMessage(lane ? control.load() : input.load(), data.data(), data.size()) < 0) {
                                std::lock_guard lock(statsMutex); ++errors;
                            }
                        }
                        std::this_thread::sleep_for(std::chrono::milliseconds(16));
                    }
                });
            } else if (type == "report") {
                char local[1024]{}, remote[1024]{};
                int selected = rtcGetSelectedCandidatePair(pc, local, sizeof(local), remote, sizeof(remote));
                std::lock_guard lock(statsMutex);
                emit({{"type", "result"}, {"inputReceived", received[0].size()}, {"inputEchoed", echoed[0].size()},
                      {"controlReceived", received[1].size()}, {"controlEchoed", echoed[1].size()},
                      {"errors", errors}, {"orderErrors", orderErrors},
                      {"selected", selected >= 0 ? json{{"local", local}, {"remote", remote}} : json(nullptr)}});
            } else if (type == "stop") break;
        }
        running = false;
        if (sender.joinable()) sender.join();
        rtcDeletePeerConnection(pc);
        rtcCleanup();
        return 0;
    } catch (const std::exception &e) {
        emit({{"type", "error"}, {"error", e.what()}});
        running = false;
        if (sender.joinable()) sender.join();
        if (pc >= 0) rtcDeletePeerConnection(pc);
        rtcCleanup();
        return 1;
    }
}
