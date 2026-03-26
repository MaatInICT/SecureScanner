import { IScanner } from '../types/scanner';

export class ScannerRegistry {
  private scanners: IScanner[] = [];

  register(scanner: IScanner): void {
    this.scanners.push(scanner);
  }

  getAll(): IScanner[] {
    return [...this.scanners];
  }

  getByName(name: string): IScanner | undefined {
    return this.scanners.find(s => s.name === name);
  }
}
