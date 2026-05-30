import { useCallback, useEffect, useRef, useState } from "react";

interface Props {
  onCapture: (blob: Blob) => void;
  onBack?: () => void;
  disabled?: boolean;
}

/**
 * Live video preview + manual "Capture" button.
 *
 * The first iteration is intentionally manual: the user frames the
 * Metatron card and taps Capture. A future iteration will run ArUco
 * detection on every frame and snap automatically when the 4 markers
 * are stable.
 */
export function CameraScanner({ onCapture, onBack, disabled }: Props) {
  const videoRef = useRef<HTMLVideoElement | null>(null);
  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const streamRef = useRef<MediaStream | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [ready, setReady] = useState(false);

  useEffect(() => {
    let cancelled = false;
    async function start() {
      try {
        const stream = await navigator.mediaDevices.getUserMedia({
          video: {
            facingMode: { ideal: "environment" },
            width: { ideal: 1920 },
            height: { ideal: 1080 },
          },
          audio: false,
        });
        if (cancelled) {
          stream.getTracks().forEach((t) => t.stop());
          return;
        }
        streamRef.current = stream;
        if (videoRef.current) {
          videoRef.current.srcObject = stream;
          await videoRef.current.play().catch(() => {});
          setReady(true);
        }
      } catch (e) {
        setError(
          e instanceof Error
            ? e.message
            : "camera unavailable (permissions?)",
        );
      }
    }
    void start();
    return () => {
      cancelled = true;
      const s = streamRef.current;
      if (s) s.getTracks().forEach((t) => t.stop());
      streamRef.current = null;
    };
  }, []);

  const capture = useCallback(() => {
    const video = videoRef.current;
    const canvas = canvasRef.current;
    if (!video || !canvas || !ready) return;
    const w = video.videoWidth;
    const h = video.videoHeight;
    canvas.width = w;
    canvas.height = h;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;
    ctx.drawImage(video, 0, 0, w, h);
    canvas.toBlob(
      (blob) => {
        if (blob) onCapture(blob);
      },
      "image/jpeg",
      0.92,
    );
  }, [onCapture, ready]);

  return (
    <div className="camera-scanner">
      {onBack && (
        <button
          type="button"
          className="secondary back-button"
          onClick={onBack}
          disabled={disabled}
        >
          Back
        </button>
      )}
      <div className="camera-frame">
        <video ref={videoRef} playsInline muted />
        <div className="camera-reticle" />
      </div>
      <canvas ref={canvasRef} style={{ display: "none" }} />
      {error && <div className="error">{error}</div>}
      <button
        className="capture-button"
        onClick={capture}
        disabled={!ready || disabled || !!error}
      >
        Capture
      </button>
    </div>
  );
}
