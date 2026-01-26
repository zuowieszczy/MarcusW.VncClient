using System.Diagnostics.CodeAnalysis;

namespace MarcusW.VncClient.Protocol.EncodingTypes
{
    /// <summary>
    /// The well known encoding types and their IDs.
    /// </summary>
    [SuppressMessage("ReSharper", "InconsistentNaming")]
    public enum WellKnownEncodingType : int
    {
        Raw = 0,
        CopyRect = 1,
        RRE = 2,
        CoRRE = 4,
        Hextile = 5,
        ZLib = 6,
        Tight = 7,
        ZLibHex = 8,
        ZRLE = 16,
        JpegEncoding = 21,
        OpenH264 = 50,
        JpegQualityLevel10 = -23,
        JpegQualityLevel09 = -24,
        JpegQualityLevel08 = -25,
        JpegQualityLevel07 = -26,
        JpegQualityLevel06 = -27,
        JpegQualityLevel05 = -28,
        JpegQualityLevel04 = -29,
        JpegQualityLevel03 = -30,
        JpegQualityLevel02 = -31,
        JpegQualityLevel01 = -32,
        DesktopSize = -223,
        LastRect = -224,
        Cursor = -239,
        XCursor = -240,
        CompressionLevel10 = -247,
        CompressionLevel09 = -248,
        CompressionLevel08 = -249,
        CompressionLevel07 = -250,
        CompressionLevel06 = -251,
        CompressionLevel05 = -252,
        CompressionLevel04 = -253,
        CompressionLevel03 = -254,
        CompressionLevel02 = -255,
        CompressionLevel01 = -256,
        QEMUPointer = -257,
        QEMUExtendedKeyEvent = -258,
        QEMUAudio = -259,
        TightPNG = -260,
        QEMULED = -261,
        giiPseudoEncoding = -305,
        DesktopName = -307,
        ExtendedDesktopSize = -308,
        xvpPseudoEncoding = -309,
        Fence = -312,
        ContinuousUpdates = -313,
        CursorWithAlpha = -314,
        ExtendedMouseButtons = -316,
        TightWithoutZlib = -317,
        JpegFineGrainedQualityLevelHigh = -412,
        JpegFineGrainedQualityLevelLow = -512,
        JpegSubsamplingLevelLow = -763,
        JpegSubsamplingLevelHigh = -768
    }
}
