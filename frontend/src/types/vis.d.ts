declare module 'vis-network' {
  export class Network {
    constructor(container: HTMLElement, data: any, options?: any);
    destroy(): void;
    on(event: string, callback: (params: any) => void): void;
    getScale(): number;
    moveTo(options: any): void;
    fit(options?: any): void;
  }
}

declare module 'vis-data' {
  export class DataSet {
    constructor(data?: any[]);
  }
}
