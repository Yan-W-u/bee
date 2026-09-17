export namespace main {
	
	export class Status {
	    step: string;
	    message: string;
	    progress: number;
	    error: string;
	    canRetry: boolean;
	
	    static createFrom(source: any = {}) {
	        return new Status(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.step = source["step"];
	        this.message = source["message"];
	        this.progress = source["progress"];
	        this.error = source["error"];
	        this.canRetry = source["canRetry"];
	    }
	}

}

