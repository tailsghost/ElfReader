#pragma once

namespace callback {
	enum BuildResult
	{
		Warn,
		Ok,
		Err
	};

	struct BuildEvent
	{
		const wchar_t* message;
		BuildResult result;
		const wchar_t* typeResult;
		int64_t timeTicks;
	};

	extern "C" {
		typedef void(__stdcall* build_callback)(const BuildEvent* ev);
	};

	static int64_t GetTimeOfDayTicks() {
		SYSTEMTIME st;
		GetLocalTime(&st);
		auto seconds = static_cast<int64_t>(st.wHour) * 3600 + static_cast<int64_t>(st.wMinute) * 60 + st.wSecond;
		auto ticks = seconds * 10000000LL;
		ticks += static_cast<int64_t>(st.wMilliseconds) * 10000LL;
		return ticks;
	}

	static const wchar_t* to_string(callback::BuildResult e)
	{
		switch (e)
		{
		case callback::Warn: return L"[Warn]";
		case callback::Ok: return L"[Ok]";
		case callback::Err: return L"[Err]";
		default: return L"[Unknown]";
		}
	}

	static void SendCallback(const wchar_t* message, callback::BuildResult result, build_callback cb)
	{
		auto type = to_string(result);
		auto timeTicks = GetTimeOfDayTicks();
		auto ev = new callback::BuildEvent();

		ev->message = _wcsdup(message);
		ev->typeResult = _wcsdup(type);
		ev->result = result;
		ev->timeTicks = timeTicks;
		if (cb) {
			cb(ev);
		}
	}

}
