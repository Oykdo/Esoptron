/// <reference types="vite/client" />
/// <reference types="vite-plugin-pwa/client" />

interface ImportMetaEnv {
  /** Base URL of the EPX-T artifact anchor (may differ from the PWA API origin). */
  readonly VITE_ANCHOR_URL?: string;
}

declare module "*.css";
declare module "*.svg" {
  const src: string;
  export default src;
}
