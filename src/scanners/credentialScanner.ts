import { Finding } from '../types/finding';
import { IScanner, ScanContext } from '../types/scanner';
import { runRules } from '../engine/ruleEngine';
import { credentialRules } from '../rules/credentialRules';

export class CredentialScanner implements IScanner {
  readonly name = 'CredentialScanner';

  scan(context: ScanContext): Finding[] {
    return runRules(credentialRules, context);
  }
}
