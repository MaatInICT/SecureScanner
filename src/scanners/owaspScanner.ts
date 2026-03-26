import { Finding } from '../types/finding';
import { IScanner, ScanContext } from '../types/scanner';
import { runRules } from '../engine/ruleEngine';
import { owaspRules } from '../rules/owaspRules';

export class OwaspScanner implements IScanner {
  readonly name = 'OwaspScanner';

  scan(context: ScanContext): Finding[] {
    return runRules(owaspRules, context);
  }
}
