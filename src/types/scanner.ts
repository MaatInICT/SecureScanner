import { Finding, FindingCategory, Severity } from './finding';

export interface IScannerRule {
  id: string;
  title: string;
  description: string;
  severity: Severity;
  category: FindingCategory;
  pattern: RegExp;
  languages?: string[];
  filePatterns?: string[];
  cweId?: string;
  owaspId?: string;
}

export interface ScanContext {
  filePath: string;
  content: string;
  languageId: string;
}

export interface IScanner {
  readonly name: string;
  scan(context: ScanContext): Finding[] | Promise<Finding[]>;
}
