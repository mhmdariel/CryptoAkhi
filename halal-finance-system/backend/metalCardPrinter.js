const EventEmitter = require('events');
const crypto = require('crypto');

class MockSerialPort {
    constructor(options) { this.path = options.path; this.baudRate = options.baudRate; this.isOpen = false; this.emitter = new EventEmitter(); }
    open(cb) { setTimeout(() => { this.isOpen = true; cb(null); this.emitter.emit('open'); }, 100); }
    write(data, cb) { setTimeout(() => { cb(null); console.log(`[SERIAL] ${data}`); }, 50); }
    on(event, listener) { this.emitter.on(event, listener); }
    close(cb) { this.isOpen = false; setTimeout(cb, 50); }
}

class MetalCardPrinter extends EventEmitter {
    constructor(options = {}) {
        super();
        this.serialPort = new MockSerialPort({ port: options.port || '/dev/ttyUSB0', baudRate: options.baudRate || 115200 });
        this.status = 'disconnected';
        this.currentJob = null;
        this.printQueue = [];
        this._setupListeners();
    }
    _setupListeners() {
        this.serialPort.on('open', () => { this.status = 'idle'; this.emit('connected'); this._processQueue(); });
        setInterval(() => { if (this.status === 'printing') this.emit('progress', { jobId: this.currentJob, progress: Math.random()*100 }); }, 2000);
    }
    async connect() {
        return new Promise((resolve, reject) => {
            this.serialPort.open(err => { if (err) { this.status = 'error'; reject(err); } else { this.status = 'idle'; resolve(); } });
        });
    }
    async disconnect() {
        return new Promise(resolve => { this.serialPort.close(() => { this.status = 'disconnected'; resolve(); }); });
    }
    queueJob(job) {
        const jobId = crypto.randomBytes(4).toString('hex');
        const fullJob = { id: jobId, ...job, status: 'queued', createdAt: new Date().toISOString() };
        this.printQueue.push(fullJob);
        this.emit('jobQueued', fullJob);
        this._processQueue();
        return jobId;
    }
    async _processQueue() {
        if (this.status !== 'idle' || this.printQueue.length === 0) return;
        const job = this.printQueue.shift();
        this.currentJob = job.id;
        this.status = 'printing';
        job.status = 'printing';
        job.startedAt = new Date().toISOString();
        this.emit('jobStarted', job);
        try {
            await this._sendCommand('STATUS');
            await this._sendCommand(`LOAD_BLANK ${job.cardData.material}`);
            await this._sendCommand(`ENGRAVE_NUMBER ${job.cardData.cardNumber}`);
            await this._sendCommand(`ENGRAVE_EXPIRY ${job.cardData.expiryMonth}/${job.cardData.expiryYear}`);
            await this._sendCommand(`ENGRAVE_CVV ${job.cardData.cvv}`);
            await this._sendCommand(`ENGRAVE_HOLDER ${job.cardData.holderName}`);
            await this._sendCommand(`EMBED_CHIP ${job.cardData.chipId || 'AUTO'}`);
            await this._sendCommand('EJECT');
            job.status = 'completed';
            job.completedAt = new Date().toISOString();
            this.emit('jobCompleted', job);
        } catch (err) {
            job.status = 'failed';
            job.error = err.message;
            this.emit('jobFailed', job);
        } finally {
            this.status = 'idle';
            this.currentJob = null;
            this._processQueue();
        }
    }
    async _sendCommand(cmd) {
        return new Promise((resolve, reject) => {
            const delay = cmd.startsWith('ENGRAVE') ? 800 : 300;
            setTimeout(() => {
                if (Math.random() < 0.01) reject(new Error('Printer error'));
                else this.serialPort.write(cmd + '\n', err => err ? reject(err) : resolve());
            }, delay);
        });
    }
    getStatus() {
        return { status: this.status, currentJob: this.currentJob, queueLength: this.printQueue.length, model: 'StainlessEtcher-Pro X9', material: '316L Stainless Steel' };
    }
    async cancelJob() {
        if (this.status === 'printing') { await this._sendCommand('ABORT'); this.status = 'idle'; this.currentJob = null; return true; }
        return false;
    }
}

module.exports = MetalCardPrinter;
