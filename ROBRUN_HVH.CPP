#include <windows.h>
#include <vector>
#include <cmath>
#include <string>
#include <MinHook.h>

#pragma comment(lib, "MinHook.x64.lib")

struct Vector3 { float x, y, z; };
struct PlayerData { void* ptr; Vector3 headPos; int health; std::string name; };

std::vector<PlayerData> g_Players;
bool g_SilentAim = true;
float g_FOV = 250.0f;

namespace Offsets {
    const DWORD64 Weapon_Fire = 0x1A2B3C0; // ЗАМЕНИ НА СВОИ ОФФСЕТЫ ПОЗЖЕ
}

typedef void(__fastcall* tFire)(void* __this, void* methodInfo, Vector3 origin, Vector3 direction);
tFire oFire = nullptr;

void __fastcall hkFire(void* __this, void* methodInfo, Vector3 origin, Vector3 direction) {
    if (!g_SilentAim) { oFire(__this, methodInfo, origin, direction); return; }
    PlayerData* target = nullptr;
    float bestDist = g_FOV;
    for (auto& p : g_Players) {
        if (p.health <= 0) continue;
        float dist = sqrtf(powf(origin.x - p.headPos.x, 2) + powf(origin.y - p.headPos.y, 2) + powf(origin.z - p.headPos.z, 2));
        if (dist < bestDist) { bestDist = dist; target = &p; }
    }
    if (target) {
        Vector3 newDir = { target->headPos.x - origin.x, target->headPos.y - origin.y, target->headPos.z - origin.z };
        float len = sqrtf(newDir.x * newDir.x + newDir.y * newDir.y + newDir.z * newDir.z);
        if (len > 0.001f) { newDir.x /= len; newDir.y /= len; newDir.z /= len; }
        oFire(__this, methodInfo, origin, newDir);
        return;
    }
    oFire(__this, methodInfo, origin, direction);
}

void RenderESP() {
    if (g_Players.empty()) return;
    HDC hdc = GetDC(FindWindowA(NULL, "ROB RUN"));
    if (!hdc) return;
    int screenW = GetSystemMetrics(SM_CXSCREEN), screenH = GetSystemMetrics(SM_CYSCREEN);
    for (auto& p : g_Players) {
        if (p.health <= 0) continue;
        Vector3 screen = { p.headPos.x * 100 + screenW / 2, -p.headPos.y * 100 + screenH / 2, 0 };
        if (screen.x < 0 || screen.x > screenW || screen.y < 0 || screen.y > screenH) continue;
        HPEN pen = CreatePen(PS_SOLID, 2, RGB(255, 0, 0));
        SelectObject(hdc, pen); SelectObject(hdc, GetStockObject(NULL_BRUSH));
        Rectangle(hdc, (int)(screen.x - 20), (int)screen.y, (int)(screen.x + 20), (int)(screen.y + 60));
        DeleteObject(pen);
    }
    ReleaseDC(FindWindowA(NULL, "ROB RUN"), hdc);
}

DWORD WINAPI CheatThread(LPVOID lpReserved) {
    while (!GetModuleHandleA("GameAssembly.dll")) Sleep(100);
    DWORD64 base = (DWORD64)GetModuleHandleA("GameAssembly.dll");
    MH_Initialize();
    MH_CreateHook((LPVOID)(base + Offsets::Weapon_Fire), &hkFire, (LPVOID*)&oFire);
    MH_EnableHook(MH_ALL_HOOKS);
    while (true) { RenderESP(); Sleep(16); }
    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);
        CreateThread(nullptr, 0, CheatThread, nullptr, 0, nullptr);
    }
    return TRUE;
}
