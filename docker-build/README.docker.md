Build these images through the host wrapper so they use your installed ASP.NET Core runtime and .NET SDK versions:

```sh
./build-docker Dockerfile -t networkmonitor-llm --load
./build-docker Dockerfile-nollama -t networkmonitor-llm-nollama --load
./build-docker Dockerfile-debian12-cpu -t networkmonitor-llm-cpu --load
```

The wrapper detects versions using `dotnet --list-runtimes` and `dotnet --version`. A local ASP.NET Core runtime and SDK are required. Direct Docker builds must supply `ASPNET_VERSION` and `DOTNET_SDK_VERSION` explicitly; neither has a default.
