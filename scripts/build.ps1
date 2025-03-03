$env:PATH = "C:/Qt/Tools/mingw530_32/bin;" + $env:PATH
cmake -G "MinGW Makefiles" -DCMAKE_BUILD_TYPE=Release -S $PSScriptRoot/../ -B $PSScriptRoot/../build
cmake --build $PSScriptRoot/../build --config Release --target all --
