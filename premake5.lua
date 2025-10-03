-- premake5.lua — автоподхват всех поддиректорий src/ и vendor/
workspace "sceNetPC"
    location "build"
    language "C++"
    configurations { "Debug", "Release" }
    platforms { "Win32", "x64" }
    startproject "app"
    cppdialect "C++14"
    symbols "On"

-- добавим helper для рекурсивного добавления include dirs
local function addAllSubdirsAsIncludes(root)
    -- совпадает с premake5: os.matchdirs поддерживает шаблоны
    local dirs = os.matchdirs(path.join(root, "**"))
    -- сам корень тоже полезно добавить
    table.insert(dirs, 1, root)
    for _, d in ipairs(dirs) do
        includedirs { d }
    end
end

filter "platforms:Win32"
    architecture "x86"
filter "platforms:x64"
    architecture "x86_64"
filter {}

project "sceNetPC"
    kind "ConsoleApp"
    language "C++"
    cppdialect "C++14"

    targetdir ("build/bin/%{cfg.platform}/%{cfg.buildcfg}")
    objdir    ("build/obj/%{cfg.platform}/%{cfg.buildcfg}")

    -- все исходники из src (включая src/include и src/src)
    files {
        "src/**.cpp",
        "src/**.c",
        "src/**.h",
        "src/**.hpp"
    }

    -- автоматически добавить все подпапки src/ в include path
    -- это решает проблему когда заголовки лежат в src/include/..., src/skel/..., src/extras/...
    addAllSubdirsAsIncludes("src")

    -- если есть vendor/ — подхватим и его подпапки (например vendor/ppsspp, vendor/glfw и т.д.)
    if os.isdir("vendor") then
        addAllSubdirsAsIncludes("vendor")
    end

    filter "system:windows"
        defines { "_CRT_SECURE_NO_WARNINGS" }
        characterset "MBCS"
    filter {}

    filter "configurations:Debug"
        defines { "DEBUG" }
        symbols "On"
        optimize "Off"
    filter "configurations:Release"
        defines { "NDEBUG" }
        optimize "On"
        symbols "Off"
    filter {}
