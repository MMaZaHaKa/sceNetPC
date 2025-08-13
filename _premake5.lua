-- premake5.lua — простая настройка для проекта в src/
workspace "win-build-test"
   configurations { "Debug", "Release" }
   platforms { "x86", "x86_64" }
   startproject "app"

-- Общие настройки проекта
project "sceNetPC"
   kind "ConsoleApp"
   language "C++"
   cppdialect "C++14"

   targetdir "bin/%{cfg.buildcfg}-%{cfg.platform}"
   objdir    "obj/%{cfg.buildcfg}-%{cfg.platform}"

   -- Включаем все исходники в src (как .cpp так и .h/.hpp)
   files { "src/**.c", "src/**.cpp", "src/**.cc", "src/**.h", "src/**.hpp" }
   includedirs { "src/include" }

-- Платформо-специфичные опции
filter "platforms:x86"
   architecture "x86"
   defines { "PLATFORM_32" }

filter "platforms:x86_64"
   architecture "x86_64"
   defines { "PLATFORM_64" }

-- Конфигурации
filter "configurations:Debug"
   defines { "DEBUG" }
   symbols "On"
   optimize "Off"

filter "configurations:Release"
   defines { "NDEBUG" }
   optimize "On"
   symbols "Off"

-- Windows-specific (если понадобится)
filter "system:windows"
   systemversion "latest"

-- сброс фильтров в конец файла
filter {}
