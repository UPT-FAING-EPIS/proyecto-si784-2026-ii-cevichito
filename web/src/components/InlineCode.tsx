import { Fragment } from "react";

/**
 * Los mensajes y lecciones de las reglas marcan el código con `acentos graves`.
 * Aquí se pintan como <code> en vez de mostrar los acentos tal cual.
 * Solo se parte el texto: nunca se interpreta HTML.
 */
export function InlineCode({ text }: { text: string }) {
  const parts = text.split("`");
  // Con un número impar de acentos el último trozo no se cierra: se deja como texto.
  const closed = parts.length % 2 === 1;
  return (
    <>
      {parts.map((p, i) => {
        const isCode = i % 2 === 1 && (closed || i < parts.length - 1);
        if (!isCode) return <Fragment key={i}>{i % 2 === 1 ? `\`${p}` : p}</Fragment>;
        return (
          <code key={i} className="rounded bg-muted px-1 py-px font-mono text-[0.9em]">
            {p}
          </code>
        );
      })}
    </>
  );
}

/** El mensaje de una regla es una plantilla por hallazgo; en el catálogo no hay hallazgo concreto. */
export function ruleTemplate(message: string) {
  return message.replace(/\{(variant|source|sink)\}/g, "…");
}
