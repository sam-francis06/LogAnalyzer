class LogAnalyzer {
    constructor() {
        this.fileInput = document.getElementById('fileInput');
        this.analyzeBtn = document.getElementById('analyzeBtn');
        this.fileInfo = document.getElementById('fileInfo');
        this.loadingDiv = document.getElementById('loadingDiv');
        this.resultsDiv = document.getElementById('resultsDiv');
        this.ipList = document.getElementById('ipList');
        this.userList = document.getElementById('userList');
        this.verdictDiv = document.getElementById('verdictDiv');
        this.statsDiv = document.getElementById('statsDiv');

        this.initEventListeners();
    }

    initEventListeners() {
        this.fileInput.addEventListener('change', (e) => this.handleFileSelect(e));
        this.analyzeBtn.addEventListener('click', () => this.analyzeLog());
    }

    handleFileSelect(event) {
        const file = event.target.files[0];
        if (file) {
            this.fileInfo.innerHTML = `
                        Selected: <strong>${file.name}</strong> (${this.formatFileSize(file.size)})
                    `;
            this.analyzeBtn.disabled = false;
        } else {
            this.fileInfo.innerHTML = '';
            this.analyzeBtn.disabled = true;
        }
    }

    formatFileSize(bytes) {
        if (bytes === 0) return '0 Bytes';
        const k = 1024;
        const sizes = ['Bytes', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    }

    async analyzeLog() {
        const file = this.fileInput.files[0];
        if (!file) return;

        this.showLoading();

        try {
            const content = await this.readFile(file);
            const analysis = this.parseLogContent(content);
            this.displayResults(analysis);
        } catch (error) {
            console.error('Error analyzing log:', error);
            this.showError('Error analyzing log file. Please check the file format.');
        }
    }

    readFile(file) {
        return new Promise((resolve, reject) => {
            const reader = new FileReader();
            reader.onload = e => resolve(e.target.result);
            reader.onerror = reject;
            reader.readAsText(file);
        });
    }

    parseLogContent(content) {
        const blocks = this.splitIntoBlocks(content);
        const ipAnalysis = this.analyzeIPs(blocks);
        const userAnalysis = this.analyzeUserBehavior(blocks);
        const isBreach = this.determineBreach(ipAnalysis, userAnalysis);

        return {
            ipAnalysis,
            userAnalysis,
            isBreach,
            stats: {
                totalBlocks: blocks.length,
                totalIPs: ipAnalysis.length,
                internalIPs: ipAnalysis.filter(ip => ip.isInternal).length,
                externalIPs: ipAnalysis.filter(ip => !ip.isInternal).length,
                suspiciousUsers: userAnalysis.filter(user => user.isSuspicious).length
            }
        };
    }

    splitIntoBlocks(content) {
        return content.split(/\n\s*\n/)
            .map(block => block.trim())
            .filter(block => block.length > 0);
    }

    analyzeIPs(blocks) {
        const ipPattern = /^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/;
        const ips = [];

        blocks.forEach(block => {
            const lines = block.split('\n');
            const firstLine = lines[0];
            const match = firstLine.match(ipPattern);

            if (match) {
                const ip = match[1];
                const isInternal = ip.startsWith('10.');

                if (!ips.find(item => item.ip === ip)) {
                    ips.push({
                        ip,
                        isInternal,
                        requests: lines.slice(1).filter(line => line.trim().length > 0)
                    });
                }
            }
        });

        return ips;
    }

    analyzeUserBehavior(blocks) {
        const userRequests = {};
        const userIdPattern = /user_id=([^&\s]+)/;

        blocks.forEach(block => {
            const lines = block.split('\n');

            lines.forEach(line => {
                const userMatch = line.match(userIdPattern);
                const timestamp = this.extractTimestamp(line);

                if (userMatch && timestamp) {
                    const userId = userMatch[1];

                    if (!userRequests[userId]) {
                        userRequests[userId] = [];
                    }

                    userRequests[userId].push({
                        timestamp,
                        request: line.trim()
                    });
                }
            });
        });

        return this.detectSuspiciousBehavior(userRequests);
    }

    extractTimestamp(line) {
        // Look for timestamp patterns like [2024-01-15 10:30:45] or similar
        const patterns = [
            /\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\]/,
            /(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})/,
            /\[(\d{2}\/\d{2}\/\d{4} \d{2}:\d{2}:\d{2})\]/,
            /(\d{2}:\d{2}:\d{2})/
        ];

        for (const pattern of patterns) {
            const match = line.match(pattern);
            if (match) {
                return new Date(match[1]);
            }
        }

        return null;
    }

    detectSuspiciousBehavior(userRequests) {
        const users = [];

        Object.entries(userRequests).forEach(([userId, requests]) => {
            if (requests.length < 2) {
                users.push({
                    userId,
                    requestCount: requests.length,
                    isSuspicious: false,
                    reason: 'Normal activity'
                });
                return;
            }

            // Sort requests by timestamp
            requests.sort((a, b) => a.timestamp - b.timestamp);

            // Check for repeated requests at regular intervals
            const intervals = [];
            for (let i = 1; i < requests.length; i++) {
                const interval = requests[i].timestamp - requests[i - 1].timestamp;
                intervals.push(interval);
            }

            // Check if most intervals are similar (within 2 seconds)
            if (intervals.length > 2) {
                const avgInterval = intervals.reduce((sum, interval) => sum + interval, 0) / intervals.length;
                const similarIntervals = intervals.filter(interval =>
                    Math.abs(interval - avgInterval) < 2000
                ).length;

                const isSuspicious = similarIntervals / intervals.length > 0.7 && avgInterval < 15000;

                users.push({
                    userId,
                    requestCount: requests.length,
                    isSuspicious,
                    reason: isSuspicious ?
                        `Repeated API hits every ${Math.round(avgInterval / 1000)}s` :
                        'Normal activity',
                    avgInterval: Math.round(avgInterval / 1000)
                });
            } else {
                users.push({
                    userId,
                    requestCount: requests.length,
                    isSuspicious: false,
                    reason: 'Insufficient data'
                });
            }
        });

        return users;
    }

    determineBreach(ipAnalysis, userAnalysis) {
        const hasExternalIPs = ipAnalysis.some(ip => !ip.isInternal);
        const hasSuspiciousUsers = userAnalysis.some(user => user.isSuspicious);

        return hasExternalIPs || hasSuspiciousUsers;
    }

    showLoading() {
        this.resultsDiv.style.display = 'none';
        this.loadingDiv.style.display = 'block';
    }

    showError(message) {
        this.loadingDiv.style.display = 'none';
        this.resultsDiv.style.display = 'block';
        this.verdictDiv.innerHTML = `
                    <div class="verdict breach">
                        ❌ Error: ${message}
                    </div>
                `;
    }

    displayResults(analysis) {
        this.loadingDiv.style.display = 'none';
        this.resultsDiv.style.display = 'block';

        this.displayStats(analysis.stats);
        this.displayIPAnalysis(analysis.ipAnalysis);
        this.displayUserAnalysis(analysis.userAnalysis);
        this.displayVerdict(analysis.isBreach);
    }

    displayStats(stats) {
        this.statsDiv.innerHTML = `
                    <div class="stat-card">
                        <div class="stat-number">${stats.totalBlocks}</div>
                        <div class="stat-label">Log Blocks</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number">${stats.totalIPs}</div>
                        <div class="stat-label">Unique IPs</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number">${stats.internalIPs}</div>
                        <div class="stat-label">Internal IPs</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number">${stats.externalIPs}</div>
                        <div class="stat-label">External IPs</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number">${stats.suspiciousUsers}</div>
                        <div class="stat-label">Suspicious Users</div>
                    </div>
                `;
    }

    displayIPAnalysis(ipAnalysis) {
        this.ipList.innerHTML = '';

        if (ipAnalysis.length === 0) {
            this.ipList.innerHTML = '<li class="ip-item">No IP addresses found in log</li>';
            return;
        }

        ipAnalysis.forEach(ip => {
            const li = document.createElement('li');
            li.className = `ip-item ${ip.isInternal ? 'ip-internal' : 'ip-external'}`;
            li.innerHTML = `
                        <span>${ip.ip}</span>
                        <span>${ip.isInternal ? '✅ Internal' : '❌ External'}</span>
                    `;
            this.ipList.appendChild(li);
        });
    }

    displayUserAnalysis(userAnalysis) {
        this.userList.innerHTML = '';

        if (userAnalysis.length === 0) {
            this.userList.innerHTML = '<li class="user-item">No user activity detected</li>';
            return;
        }

        userAnalysis.forEach(user => {
            const li = document.createElement('li');
            li.className = `user-item ${user.isSuspicious ? 'user-suspicious' : 'user-normal'}`;
            li.innerHTML = `
                        <div>
                            <strong>User: ${user.userId}</strong><br>
                            <small>${user.reason} (${user.requestCount} requests)</small>
                        </div>
                        <span>${user.isSuspicious ? '⚠️ Suspicious' : '✅ Normal'}</span>
                    `;
            this.userList.appendChild(li);
        });
    }

    displayVerdict(isBreach) {
        const verdictClass = isBreach ? 'breach' : 'safe';
        const verdictText = isBreach ? '🚨 Breach Detected!' : '✅ System Safe';
        const verdictDescription = isBreach ?
            'Suspicious activity or external access detected in the logs.' :
            'No suspicious activity detected. All systems appear normal.';

        this.verdictDiv.className = `verdict ${verdictClass}`;
        this.verdictDiv.innerHTML = `
                    <div>${verdictText}</div>
                    <div style="font-size: 0.8em; margin-top: 10px; font-weight: normal;">
                        ${verdictDescription}
                    </div>
                `;
    }
}

// Initialize the application
document.addEventListener('DOMContentLoaded', () => {
    new LogAnalyzer();
});