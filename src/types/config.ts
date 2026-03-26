import { FindingCategory, Severity } from './finding';

export interface SecureScannerConfig {
  enableOnSave: boolean;
  enableOnOpen: boolean;
  severityThreshold: Severity;
  ignorePaths: string[];
  enabledCategories: FindingCategory[];
  maxFileSizeKB: number;
}
