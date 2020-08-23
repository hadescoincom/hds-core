// Copyright 2020 The Hds Team
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#pragma once
#include "reactor.h"
#include "../common.h" // IMPLEMENT_GET_PARENT_OBJ

namespace hds { namespace io {

class Timer : protected Reactor::Object {
public:
    using Ptr = std::unique_ptr<Timer>;
    using Callback = std::function<void()>;

    /// Creates a new timer object, throws on errors
    static Ptr create(Reactor& reactor);

    /// Starts the timer
    Result start(unsigned intervalMsec, bool isPeriodic, Callback callback);

    /// Restarts the timer if callbackis already set
    Result restart(unsigned intervalMsec, bool isPeriodic);

    /// Cancels the timer. May be called from anywhere in timer's thread
    void cancel();

private:
    Timer() = default;

    Callback _callback;
};

struct IdleEvt
{
    ~IdleEvt() { cancel(); }

    void start();
    void cancel();

    virtual void OnSchedule() {}

private:

    struct Handle
        :public uv_idle_t
    {
        static void CallbackRaw(uv_idle_t*);

        IMPLEMENT_GET_PARENT_OBJ(IdleEvt, m_Handle)
    } m_Handle;

    bool m_Set = false;
};

}} //namespaces

