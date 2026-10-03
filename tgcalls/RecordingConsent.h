#pragma once

#include <cstdint>
#include <functional>
#include <string>
#include <set>

namespace tgcalls {

struct RecordingConsentSnapshot {
    int capability = -1; // Unknown until authenticated setup; 0 unsupported, 1 supported.
    std::string incomingToken;
    std::string outgoingToken;
    int outgoingStatus = 0; // Idle, waiting, accepted, declined, timed out.
};

class RecordingConsent {
public:
    using Send = std::function<void(const std::string &, const std::string &)>;
    static bool validToken(const std::string &token) {
        if (token.size() != 36) return false;
        for (size_t i = 0; i != token.size(); ++i) {
            const char c = token[i];
            if (i == 8 || i == 13 || i == 18 || i == 23) {
                if (c != '-') return false;
            } else if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
        }
        return true;
    }
    static bool validAction(const std::string &action) {
        return action == "request" || action == "accept" || action == "decline" || action == "cancel";
    }
    void negotiate(bool supported) {
        if (_state.capability == -1) _state.capability = supported ? 1 : 0;
    }
    RecordingConsentSnapshot command(const std::string &action, const std::string &token, int64_t now, const Send &send) {
        expire(now, send);
        if (_state.capability != 1 || !validToken(token)) return _state;
        if (action == "request" && token != _state.outgoingToken && _state.outgoingStatus != 1) {
            _state.outgoingToken = token;
            _state.outgoingStatus = 1;
            _outgoingDeadline = now + 30000;
            send(token, "request");
        } else if (action == "cancel" && token == _state.outgoingToken) {
            send(token, "cancel");
            _state.outgoingToken.clear();
            _state.outgoingStatus = 0;
        } else if ((action == "accept" || action == "decline") && token == _state.incomingToken) {
            _state.incomingToken.clear();
            send(token, action);
        }
        return _state;
    }
    void receive(const std::string &token, const std::string &action, int64_t now, const Send &send) {
        expire(now, send);
        if (_state.capability != 1 || !validToken(token) || !validAction(action)) return;
        if (action == "request") {
            // A request can prompt only once in this call. Bound memory even for
            // a misbehaving authenticated peer; duplicates never extend expiry.
            if (_seen.count(token)) return;
            if (_seen.size() >= 64) { send(token, "decline"); return; }
            _seen.insert(token);
            if (!_state.incomingToken.empty()) { send(token, "decline"); return; }
            _state.incomingToken = token;
            _incomingDeadline = now + 30000;
        } else if (action == "cancel" && token == _state.incomingToken) {
            _state.incomingToken.clear();
        } else if ((action == "accept" || action == "decline") &&
                   token == _state.outgoingToken && _state.outgoingStatus == 1) {
            _state.outgoingStatus = action == "accept" ? 2 : 3;
        }
    }
private:
    void expire(int64_t now, const Send &send) {
        if (!_state.incomingToken.empty() && now >= _incomingDeadline) {
            send(_state.incomingToken, "decline");
            _state.incomingToken.clear();
        }
        if (_state.outgoingStatus == 1 && now >= _outgoingDeadline) {
            send(_state.outgoingToken, "cancel");
            _state.outgoingStatus = 4;
        }
    }
    RecordingConsentSnapshot _state;
    std::set<std::string> _seen;
    int64_t _incomingDeadline = 0;
    int64_t _outgoingDeadline = 0;
};

} // namespace tgcalls
