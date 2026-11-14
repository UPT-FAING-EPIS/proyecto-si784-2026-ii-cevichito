import { useAuth } from "@/auth/AuthProvider";
import { PageHeader } from "@/components/PageHeader";

// Afirmaciones tomadas de la columna "se puede afirmar" (sección 2.3 de docs/spec/especificacion.md).
const CAN = [
  "Cada regla explica en español qué es el problema, por qué es peligroso y cómo corregirlo, con un ejemplo vulnerable y otro corregido, y su referencia a CWE y OWASP Top 10.",
  "Se usa sin instalar nada en tu equipo: pegas código, subes un ZIP o indicas un repositorio público de GitHub.",
  "Es gratuito y se instala en tu propio servidor con Docker y PostgreSQL; el código no sale de ese servidor.",
  "Guarda el historial de cada proyecto: qué hallazgos son nuevos, cuáles se corrigieron, cuáles persisten o se reabrieron, y el tiempo mediano hasta corregir por severidad.",
  "Exporta SARIF 2.1.0 (compatible con GitHub Code Scanning y DefectDojo), JSON y HTML.",
  "En Python sigue el recorrido de los datos (taint) dentro de un mismo archivo, también entre funciones de ese archivo.",
];

const CANNOT = [
  "No detecta «más» ni «mejor» que Semgrep, CodeQL, SonarQube o Snyk.",
  "No analiza entre archivos distintos.",
  "En JavaScript y otros lenguajes solo busca patrones de texto línea a línea; esas reglas están marcadas como heurísticas y de confianza baja.",
  "No cubre todo OWASP Top 10: algunas categorías, como el diseño inseguro, no se pueden detectar con análisis estático.",
  "No sirve como prueba de cumplimiento normativo (PCI, ISO) ni garantiza que el código esté libre de fallos.",
];

export default function About() {
  const { config } = useAuth();
  return (
    <>
      <PageHeader title="Acerca de SAST Studio" />
      <div className="grid max-w-prose gap-6">
        <p>
          SAST Studio es un analizador estático de seguridad pensado para aprender. Revisa el código sin ejecutarlo, señala
          patrones peligrosos y acompaña cada hallazgo de una explicación y una corrección. Nació como proyecto de la
          asignatura de Calidad de Software.
        </p>
        <section aria-labelledby="puede">
          <h2 id="puede" className="mb-2 text-md font-semibold">
            Qué hace
          </h2>
          <ul className="grid list-disc gap-1.5 pl-5">
            {CAN.map((c) => (
              <li key={c}>{c}</li>
            ))}
          </ul>
        </section>
        <section aria-labelledby="no-puede">
          <h2 id="no-puede" className="mb-2 text-md font-semibold">
            Qué no hace
          </h2>
          <ul className="grid list-disc gap-1.5 pl-5">
            {CANNOT.map((c) => (
              <li key={c}>{c}</li>
            ))}
          </ul>
        </section>
        <p className="text-sm text-muted-foreground">
          La precisión y la cobertura se miden sobre un corpus anotado con un script reproducible; los resultados están en{" "}
          <code className="text-sm">docs/benchmark.md</code> del repositorio.
          {config && <> Versión del motor: <span className="font-mono">{config.version}</span>.</>}
        </p>
      </div>
    </>
  );
}
