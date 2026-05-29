/// <reference types="vite/client" />
/// <reference types="vite-plugin-pwa/client" />

declare module "*.css";
declare module "*.svg" {
  const src: string;
  export default src;
}
