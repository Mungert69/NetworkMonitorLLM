using NetworkMonitor.Objects.ServiceMessage;
using System;
using System.IO;
using System.Linq;
using Microsoft.CodeAnalysis;
using System.Text.RegularExpressions;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Xunit;

namespace NetworkMonitor.LLM.Services;

public class ConnectExpertStatusContractTests
{
    [Fact]
    public void PromptUsesCompleteMeasurementContract()
    {
        var prompt = Assert.Single(new ConnectExpertToolsBuilder()
            .GetSystemPrompt("now", new LLMServiceObj(), "TurboLLM")).Content;
        Assert.Contains("public virtual EndpointMeasurementMetadata Measurement", prompt);
        Assert.Contains("physical value - Measurement.Offset", prompt);
        Assert.Contains("public sealed record EndpointMeasurementMetadata", prompt);
        Assert.Contains("TimingRatingThresholds? TimingRatingThresholds = null", prompt);
        Assert.Contains("connect_type must not contain the word Connect", prompt);
        Assert.DoesNotContain("public virtual string Unit", prompt);
        Assert.DoesNotContain("public virtual double Scale", prompt);
        Assert.DoesNotContain("public override string Unit", prompt);
    }

    [Fact]
    public void Prompt_ExplainsDeclarationDiagnosticsAndRetry()
    {
        var prompt = Assert.Single(new ConnectExpertToolsBuilder()
            .GetSystemPrompt("2026-10-03", new LLMServiceObj(), "TurboLLM")).Content;
        Assert.Contains("IReadOnlyCollection<string> StatusLabels", prompt);
        Assert.Contains("literal strings only", prompt);
        Assert.Contains("ProcessException's second argument", prompt);
        Assert.Contains("Do not assign MpiConnect.PingInfo.Status directly", prompt);
        Assert.Contains("resubmit", prompt);
        Assert.Contains("Invalid connect status", prompt);
    }

    [Fact]
    public void AddConnectSchema_RequiresFixedLiteralLabels()
    {
        var parameters = ConnectTools.BuildAddFunction().Parameters;
        Assert.NotNull(parameters);
        Assert.NotNull(parameters.Properties);
        var description = parameters.Properties["source_code"].Description;
        Assert.Contains("StatusLabels", description);
        Assert.Contains("literal labels", description);
        Assert.Contains("changing values in diagnostics", description);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void FewShotExamples_DeclareEveryOutcomeLabel(bool xml)
    {
        var text = string.Join("\n", NShotPromptFactory.GetStaticPrompt("connect", xml)
            .Select(m => m.Content));
        var examples = Regex.Matches(text, @"<!\[CDATA\[(.*?)\]\]>", RegexOptions.Singleline);
        Assert.Equal(4, examples.Count);
        foreach (Match example in examples)
        {
            var tree = CSharpSyntaxTree.ParseText(example.Groups[1].Value);
            var root = tree.GetRoot();
            // Bind every example against the current library, not a copied base class.
            var references = ((string)AppContext.GetData("TRUSTED_PLATFORM_ASSEMBLIES")!).Split(Path.PathSeparator)
                .Select(path => MetadataReference.CreateFromFile(path));
            var compilation = CSharpCompilation.Create("ConnectExample", new[] { tree }, references,
                new CSharpCompilationOptions(OutputKind.DynamicallyLinkedLibrary));
            Assert.Empty(compilation.GetDiagnostics().Where(d => d.Severity == DiagnosticSeverity.Error));
            Assert.Single(root.DescendantNodes().OfType<PropertyDeclarationSyntax>(),
                p => p.Identifier.ValueText == "Measurement");
            var className = Assert.Single(root.DescendantNodes().OfType<ClassDeclarationSyntax>()).Identifier.ValueText;
            if (className != "SupplyVoltageConnect")
                Assert.Contains("Timer.Start()", example.Groups[1].Value);
            var property = Assert.Single(root.DescendantNodes().OfType<PropertyDeclarationSyntax>(),
                p => p.Identifier.ValueText == "StatusLabels");
            var array = Assert.IsType<ImplicitArrayCreationExpressionSyntax>(property.ExpressionBody!.Expression);
            var labels = array.Initializer.Expressions.Cast<LiteralExpressionSyntax>()
                .Select(e => e.Token.ValueText).ToHashSet();
            foreach (var call in root.DescendantNodes().OfType<InvocationExpressionSyntax>())
            {
                var name = (call.Expression as IdentifierNameSyntax)?.Identifier.ValueText;
                if (name != "ProcessStatus" && name != "ProcessException") continue;
                var expression = call.ArgumentList.Arguments[name == "ProcessStatus" ? 0 : 1].Expression;
                var literal = Assert.IsType<LiteralExpressionSyntax>(expression);
                Assert.Contains(literal.Token.ValueText, labels);
            }
        }
    }
}
