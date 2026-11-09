interface ImportMetaEnv {
  readonly MANTEL_FLAVOR?: string;
  readonly MANTEL_BUILD_TIME?: string;
  readonly MANTEL_API_URL?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
