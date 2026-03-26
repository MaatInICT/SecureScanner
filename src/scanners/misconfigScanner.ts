import { Finding } from '../types/finding';
import { IScanner, ScanContext } from '../types/scanner';
import { runRules } from '../engine/ruleEngine';
import { misconfigRules } from '../rules/misconfigRules';

export class MisconfigScanner implements IScanner {
  readonly name = 'MisconfigScanner';

  scan(context: ScanContext): Finding[] {
    return runRules(misconfigRules, context);
  }
}
