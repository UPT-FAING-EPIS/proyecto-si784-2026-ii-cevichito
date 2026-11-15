import { python } from "@codemirror/lang-python";
import { HighlightStyle, syntaxHighlighting } from "@codemirror/language";
import { EditorView } from "@codemirror/view";
import { tags as t } from "@lezer/highlight";
import CodeMirror from "@uiw/react-codemirror";

// Tema del editor a partir de los tokens: funciona igual en claro y oscuro.
const theme = EditorView.theme({
  "&": { backgroundColor: "var(--surface)", color: "var(--foreground)", fontSize: "13px" },
  ".cm-content": { fontFamily: "var(--font-mono)", caretColor: "var(--foreground)" },
  ".cm-gutters": { backgroundColor: "var(--muted)", color: "var(--muted-foreground)", border: "none" },
  ".cm-activeLine": { backgroundColor: "var(--muted)" },
  ".cm-activeLineGutter": { backgroundColor: "var(--border)" },
  "&.cm-focused": { outline: "2px solid var(--ring)", outlineOffset: "-1px" },
  "&.cm-focused .cm-selectionBackground, .cm-selectionBackground": { backgroundColor: "var(--selection)" },
  ".cm-cursor": { borderLeftColor: "var(--foreground)" },
});

const highlight = HighlightStyle.define([
  { tag: [t.keyword, t.controlKeyword, t.operatorKeyword, t.definitionKeyword], color: "var(--code-keyword)" },
  { tag: [t.string, t.special(t.string)], color: "var(--code-string)" },
  { tag: [t.number, t.bool, t.null], color: "var(--code-number)" },
  { tag: [t.comment, t.lineComment], color: "var(--code-comment)", fontStyle: "italic" },
  { tag: [t.function(t.variableName), t.definition(t.function(t.variableName))], fontWeight: "600" },
]);

export function CodeEditor({
  value,
  onChange,
  python: isPython,
  labelledBy,
  height = "360px",
  placeholder = "Pega aquí el código que quieres analizar",
}: {
  value: string;
  onChange: (v: string) => void;
  python: boolean;
  labelledBy: string;
  height?: string;
  placeholder?: string;
}) {
  return (
    <div className="overflow-hidden rounded border border-input">
      <CodeMirror
        value={value}
        onChange={onChange}
        height={height}
        theme="none"
        basicSetup={{ syntaxHighlighting: false, foldGutter: false, highlightActiveLineGutter: true }}
        extensions={[theme, syntaxHighlighting(highlight), ...(isPython ? [python()] : [])]}
        aria-labelledby={labelledBy}
        placeholder={placeholder}
      />
    </div>
  );
}
