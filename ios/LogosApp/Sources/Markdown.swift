import Foundation

/// Renders AI-generated markdown into an `AttributedString` for display in SwiftUI `Text`.
/// SwiftUI only auto-parses markdown from string *literals*, so AI replies (runtime
/// strings) otherwise show raw `**`/`-`. Inline syntax (bold/italic/code/links) renders;
/// list markers (`-`/`*`/`+`) become "•" and `#` headings become bold, so nothing leaks
/// stray asterisks. Use ONLY for AI/assistant text — never user or peer messages, which
/// must render exactly as typed.
enum Markdown {
    static func render(_ raw: String) -> AttributedString {
        let lines = raw.replacingOccurrences(of: "\r\n", with: "\n").components(separatedBy: "\n")
        var out = AttributedString()
        for (i, original) in lines.enumerated() {
            var line = original
            var prefix = ""
            if let r = line.range(of: #"^(\s*)[-*+]\s+"#, options: .regularExpression) {
                // Bullet list item → "• …"
                let match = String(line[r])
                let indent = String(match.prefix(while: { $0 == " " || $0 == "\t" }))
                prefix = indent + "•  "
                line = String(line[r.upperBound...])
            } else if let r = line.range(of: #"^\s*#{1,6}\s+"#, options: .regularExpression) {
                // Heading → bold the remainder
                line = "**" + String(line[r.upperBound...]) + "**"
            }
            let rendered = (try? AttributedString(
                markdown: line,
                options: .init(interpretedSyntax: .inlineOnlyPreservingWhitespace)))
                ?? AttributedString(line)
            out += AttributedString(prefix) + rendered
            if i < lines.count - 1 { out += AttributedString("\n") }
        }
        return out
    }
}
