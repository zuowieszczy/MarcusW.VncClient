using Avalonia;
using Avalonia.Controls;
using Avalonia.Logging;
using Avalonia.ReactiveUI;

namespace AvaloniaVncClient
{
    public static class Program
    {
        // Initialization code. Don't use any Avalonia, third-party APIs or any
        // SynchronizationContext-reliant code before AppMain is called: things aren't initialized
        // yet and stuff might break.
        public static void Main(string[] args)
            => BuildAvaloniaApp().StartWithClassicDesktopLifetime(args, ShutdownMode.OnMainWindowClose);

        // Avalonia configuration, don't remove; also used by visual designer.
        public static AppBuilder BuildAvaloniaApp()
        {
#if DEBUG
            LogEventLevel logLevel = LogEventLevel.Debug;
#else
            LogEventLevel logLevel = LogEventLevel.Warning;
#endif
            // Enable Skia GPU rendering with a 256 MB (256*1024*1024) resource cache.
            //return AppBuilder.Configure<App>().UsePlatformDetect().With(new SkiaOptions {MaxGpuResourceSizeBytes=256*1024*1024}).With(new Win32PlatformOptions { RenderingMode = [Win32RenderingMode.AngleEgl] }).LogToTrace(logLevel).UseReactiveUI();
            return AppBuilder.Configure<App>().UsePlatformDetect().With(new SkiaOptions { MaxGpuResourceSizeBytes = 256 * 1024 * 1024 }).LogToTrace(logLevel).UseReactiveUI();
        }
    }
}
