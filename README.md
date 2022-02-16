# dll_injector
simple dll injector for windows, done without calling the winapi function "LoadLibrary" so it can bypass some anticheats; but it's still insanely easy to detect, ps: shit code.

usage: dllname_procname, i.e, if you want to inject a dll named x.dll into a process called y.exe, name the injector as x_y.
