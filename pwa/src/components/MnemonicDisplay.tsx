import { useMemo, useState } from "react";

interface Props {
  words: string[];
  onConfirmed: () => void;
}

/**
 * Two-step recovery phrase display.
 *
 * 1. Show the 24 words, ask the user to write them down.
 * 2. Quiz the user on 3 random positions to verify they actually copied
 *    the phrase. Only then expose the "I saved it" button.
 *
 * The phrase is rendered into the DOM only after explicit user gesture
 * to mitigate accidental screen captures or shoulder-surfing.
 */
export function MnemonicDisplay({ words, onConfirmed }: Props) {
  const [revealed, setRevealed] = useState(false);
  const [step, setStep] = useState<"reveal" | "quiz">("reveal");
  const quizPositions = useMemo(() => {
    const set = new Set<number>();
    while (set.size < 3) set.add(Math.floor(Math.random() * words.length));
    return Array.from(set).sort((a, b) => a - b);
  }, [words.length]);
  const [quizAnswers, setQuizAnswers] = useState<Record<number, string>>({});
  const allCorrect = quizPositions.every(
    (i) => (quizAnswers[i] ?? "").trim().toLowerCase() === words[i],
  );

  if (step === "reveal") {
    return (
      <div className="mnemonic">
        <h2>Your recovery phrase</h2>
        <p className="warn">
          Write these 24 words on paper. They cannot be recovered if you lose
          them. They are the only way to restore your enrollment.
        </p>
        {!revealed ? (
          <button onClick={() => setRevealed(true)} className="primary">
            Show recovery phrase
          </button>
        ) : (
          <>
            <ol className="words">
              {words.map((w, i) => (
                <li key={i}>
                  <span className="idx">{i + 1}</span>
                  <span className="word">{w}</span>
                </li>
              ))}
            </ol>
            <button onClick={() => setStep("quiz")} className="primary">
              I wrote it down — verify me
            </button>
          </>
        )}
      </div>
    );
  }

  return (
    <div className="mnemonic">
      <h2>Verify your recovery phrase</h2>
      <p>Type the words at the requested positions.</p>
      {quizPositions.map((i) => (
        <label key={i} className="quiz-row">
          <span>Word #{i + 1}</span>
          <input
            type="text"
            autoComplete="off"
            autoCapitalize="none"
            spellCheck={false}
            value={quizAnswers[i] ?? ""}
            onChange={(e) =>
              setQuizAnswers((q) => ({ ...q, [i]: e.target.value }))
            }
          />
        </label>
      ))}
      <button onClick={onConfirmed} disabled={!allCorrect} className="primary">
        Confirm and continue
      </button>
      <button onClick={() => setStep("reveal")} className="secondary">
        Back to phrase
      </button>
    </div>
  );
}
