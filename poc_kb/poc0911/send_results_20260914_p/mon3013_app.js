function firewallLogsApp() {
	return {
		logs: [],
		currentPage: 1,
		totalPages: 1,
		total: 0,
		pageSize: 25,
		pollInterval: 5,
		autoRefresh: true,
		pollTimer: null,
		isFetching: false,
		lastUpdate: "从未更新",
		startTime: "",
		endTime: "",

		// 当前厂商过滤：''=全部 | h3c | dptech
		source: "",

		// 各厂商日志计数（供 Tab 展示）
		sourceCounts: { all: 0, h3c: 0, dptech: 0 },

		// 连接状态：connecting | sse | polling
		connectionMode: "connecting",

		// SSE 连接管理
		sseConnection: null,
		pendingSSEConnection: null,
		pendingSSEConnectTimeoutTimer: null,
		sseConnectTimeout: 5000,
		sseRecoveryTimer: null,
		sseRecoveryInterval: 30000,

		init() {
			const now = new Date();
			const startOfDay = new Date(
				now.getFullYear(),
				now.getMonth(),
				now.getDate(),
			);
			this.startTime = this.formatDateTimeInput(startOfDay);

			// 先拉一次列表，保证页面初始有数据；然后优先尝试 SSE。
			this.fetchLogs();
			this.connectSSE({ keepPolling: false });
		},

		async fetchLogs() {
			if (this.isFetching) {
				return;
			}

			this.isFetching = true;
			let success = false;

			try {
				const params = new URLSearchParams({
					page: this.currentPage,
					page_size: this.pageSize,
				});

				if (this.source) {
					params.append("source", this.source);
				}

				if (this.startTime) {
					params.append("start_time", this.startTime.replace("T", " ") + ":00");
				}
				if (this.endTime) {
					params.append("end_time", this.endTime.replace("T", " ") + ":00");
				}

				const response = await fetch(`/api/logs?${params}`);
				const data = await response.json();

				if (data.code === 200) {
					this.logs = Array.isArray(data.data) ? data.data : [];
					this.total = data.total || 0;
					this.totalPages = Math.ceil(this.total / Number(this.pageSize)) || 1;
					this.currentPage = data.page || 1;
					this.updateSourceCounts(data.source_counts);
					success = true;
				} else {
					console.error("获取日志失败:", data.message);
				}
			} catch (error) {
				console.error("获取日志时出错:", error);
			} finally {
				this.isFetching = false;
				const nowText = new Date().toLocaleString("zh-CN");
				this.lastUpdate = success
					? `最后更新: ${nowText}`
					: `更新失败: ${nowText}`;
			}
		},

		refreshLogs() {
			this.currentPage = 1;
			this.fetchLogs();
		},

		// 切换厂商 Tab
		setSource(source) {
			if (this.source === source) return;
			this.source = source;
			this.currentPage = 1;
			this.fetchLogs();
		},

		// 更新各厂商 Tab 徽标（使用后端统计的真实总数）
		updateSourceCounts(sourceCounts) {
			const counts = sourceCounts || {};
			this.sourceCounts = {
				all: counts.all || 0,
				h3c: counts.h3c || 0,
				dptech: counts.dptech || 0,
			};
		},

		// 日志来源显示名
		sourceLabel(source) {
			if (source === "h3c") return "H3C";
			if (source === "dptech") return "迪普";
			return source || "未知";
		},

		goToPage(page) {
			if (page < 1 || page > this.totalPages) return;
			this.currentPage = page;
			this.fetchLogs();
		},

		onPageSizeChange() {
			this.refreshLogs();
		},

		onPollIntervalChange() {
			if (this.connectionMode === "polling") {
				this.startPolling();
			}
		},

		startPolling() {
			this.stopPolling();

			if (!this.autoRefresh || this.connectionMode === "sse") {
				return;
			}

			const seconds = Number(this.pollInterval);
			const interval =
				Number.isFinite(seconds) && seconds > 0 ? seconds * 1000 : 5000;

			this.pollTimer = setInterval(() => {
				this.fetchLogs();
			}, interval);
		},

		stopPolling() {
			if (this.pollTimer) {
				clearInterval(this.pollTimer);
				this.pollTimer = null;
			}
		},

		toggleAutoRefresh() {
			this.autoRefresh = !this.autoRefresh;

			if (this.connectionMode === "polling") {
				if (this.autoRefresh) {
					this.startPolling();
				} else {
					this.stopPolling();
				}
			}
		},

		resetFilters() {
			const now = new Date();
			const startOfDay = new Date(
				now.getFullYear(),
				now.getMonth(),
				now.getDate(),
			);
			this.startTime = this.formatDateTimeInput(startOfDay);
			this.endTime = "";
			this.currentPage = 1;
			this.source = "";
			this.refreshLogs();
		},

		formatTimestamp(timestamp) {
			if (!timestamp) return "N/A";
			return timestamp;
		},

		formatDateTimeInput(date) {
			const year = date.getFullYear();
			const month = String(date.getMonth() + 1).padStart(2, "0");
			const day = String(date.getDate()).padStart(2, "0");
			const hours = String(date.getHours()).padStart(2, "0");
			const minutes = String(date.getMinutes()).padStart(2, "0");

			return `${year}-${month}-${day}T${hours}:${minutes}`;
		},

		getSeverityClass(severity) {
			if (!severity) return "is-light";

			const severityMap = {
				Low: "is-success",
				Medium: "is-warning",
				High: "is-danger",
				Critical: "is-dark",
			};

			return severityMap[severity] || "is-light";
		},

		// 厂商标签样式：H3C 蓝色 / 迪普紫色（is-link 为 Bulma 蓝色）
		newLogSourceClass(source) {
			if (source === "h3c") return "is-info";
			if (source === "dptech") return "is-link";
			return "is-light";
		},

		connectSSE({ keepPolling = false } = {}) {
			if (!window.EventSource) {
				console.warn("浏览器不支持 SSE，使用轮询模式");
				if (!keepPolling) this.switchToPolling();
				return;
			}

			this.cleanupPendingSSE();

			if (!keepPolling) {
				this.cleanupSSE();
				this.stopPolling();
				this.connectionMode = "connecting";
			}

			try {
				const connection = new EventSource("/api/logs/stream");
				this.pendingSSEConnection = connection;

				connection.addEventListener("connected", (e) => {
					if (this.pendingSSEConnection !== connection) {
						connection.close();
						return;
					}

					console.log(keepPolling ? "SSE 恢复成功" : "SSE 连接已建立", e.data);
					this.clearPendingSSEConnectTimeout();
					this.pendingSSEConnection = null;
					this.cleanupSSE();
					this.sseConnection = connection;
					this.switchToSSE();
				});

				connection.addEventListener("log", (e) => {
					if (
						this.sseConnection === connection &&
						this.connectionMode === "sse"
					) {
						this.handleSSELog(e);
					}
				});

				connection.onerror = (err) => {
					console.error(keepPolling ? "SSE 恢复探测失败" : "SSE 连接错误", err);

					if (this.pendingSSEConnection === connection) {
						this.cleanupPendingSSE();
						if (!keepPolling) this.switchToPolling();
						return;
					}

					if (this.sseConnection === connection) {
						this.switchToPolling();
					}
				};

				this.pendingSSEConnectTimeoutTimer = setTimeout(() => {
					if (this.pendingSSEConnection === connection) {
						console.warn(
							keepPolling
								? "SSE 恢复探测超时，继续保持轮询"
								: "SSE 连接超时，切换到轮询",
						);
						this.cleanupPendingSSE();
						if (!keepPolling) this.switchToPolling();
					}
				}, this.sseConnectTimeout);
			} catch (error) {
				console.error(
					keepPolling ? "SSE 恢复探测初始化失败" : "SSE 初始化失败",
					error,
				);
				this.cleanupPendingSSE();
				if (!keepPolling) this.switchToPolling();
			}
		},

		switchToSSE() {
			this.connectionMode = "sse";
			this.stopPolling();
			this.clearSSERecoveryTimer();
			this.lastUpdate = `最后更新: ${new Date().toLocaleString("zh-CN")} (实时推送)`;
		},

		switchToPolling() {
			this.cleanupSSE();
			this.cleanupPendingSSE();
			this.connectionMode = "polling";
			this.startPolling();
			this.startSSERecoveryTimer();
		},

		shouldInsertSSELog() {
			// 保持简单：只在第一页且没有固定结束时间时插入实时日志。
			// 用户查看历史窗口或翻页时，实时日志不污染当前列表，等待手动刷新或轮询刷新。
			return Number(this.currentPage) === 1 && !this.endTime;
		},

		handleSSELog(e) {
			try {
				const newLog = JSON.parse(e.data);

				// 实时更新 Tab 徽标计数（先计数再过滤，保证徽标始终准确）
				this.sourceCounts.all++;
				if (newLog.source === "h3c") {
					this.sourceCounts.h3c++;
				} else if (newLog.source === "dptech") {
					this.sourceCounts.dptech++;
				}

				// 厂商过滤：当前选中特定厂商时，其他厂商的实时日志不插入
				if (this.source && newLog.source !== this.source) {
					return;
				}

				const existingIndex = this.logs.findIndex(
					(log) => log.id === newLog.id,
				);

				if (existingIndex !== -1) {
					this.logs[existingIndex] = newLog;
				} else if (this.shouldInsertSSELog()) {
					this.logs.unshift(newLog);
					this.total++;

					if (this.logs.length > Number(this.pageSize)) {
						this.logs.pop();
					}
				}

				this.totalPages = Math.ceil(this.total / Number(this.pageSize)) || 1;
				this.lastUpdate = `最后更新: ${new Date().toLocaleString("zh-CN")} (实时推送)`;
			} catch (err) {
				console.error("解析 SSE 日志数据失败", err);
			}
		},

		startSSERecoveryTimer() {
			this.clearSSERecoveryTimer();

			this.sseRecoveryTimer = setInterval(() => {
				if (this.connectionMode === "polling") {
					this.connectSSE({ keepPolling: true });
				}
			}, this.sseRecoveryInterval);
		},

		clearSSERecoveryTimer() {
			if (this.sseRecoveryTimer) {
				clearInterval(this.sseRecoveryTimer);
				this.sseRecoveryTimer = null;
			}
		},

		clearPendingSSEConnectTimeout() {
			if (this.pendingSSEConnectTimeoutTimer) {
				clearTimeout(this.pendingSSEConnectTimeoutTimer);
				this.pendingSSEConnectTimeoutTimer = null;
			}
		},

		cleanupPendingSSE() {
			if (this.pendingSSEConnection) {
				this.pendingSSEConnection.close();
				this.pendingSSEConnection = null;
			}

			this.clearPendingSSEConnectTimeout();
		},

		cleanupSSE() {
			if (this.sseConnection) {
				this.sseConnection.close();
				this.sseConnection = null;
			}
		},
	};
}
