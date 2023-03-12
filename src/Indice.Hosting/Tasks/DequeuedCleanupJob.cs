﻿using Indice.Hosting.Services;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Quartz;

namespace Indice.Hosting.Tasks;

[PersistJobDataAfterExecution]
internal class DequeuedCleanupJob<TWorkItem> : IJob where TWorkItem : class
{
    private readonly IMessageQueue<TWorkItem> _workItemQueue;
    private readonly ILogger<DequeuedCleanupJob<TWorkItem>> _logger;
    private readonly IConfiguration _configuration;

    public DequeuedCleanupJob(IMessageQueue<TWorkItem> workItemQueue, ILogger<DequeuedCleanupJob<TWorkItem>> logger, IConfiguration configuration) {
        _workItemQueue = workItemQueue ?? throw new ArgumentNullException(nameof(workItemQueue));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
    }

    public async Task Execute(IJobExecutionContext context) {
        _logger.LogInformation("Queue cleanup job run at: {TimeStamp}", DateTime.UtcNow);
        var jobDataMap = context.JobDetail.JobDataMap;
        var queueName = jobDataMap.GetString(JobDataKeys.QueueName);
        var cleanUpBatchSize = jobDataMap.GetInt(JobDataKeys.CleanUpBatchSize);
        try {
            await _workItemQueue.Cleanup(cleanUpBatchSize);
        } catch (Exception exception) {
            _logger.LogError("An error occurred while Cleaning up queue '{QueueName}'. Exception is: {Exception}", queueName, exception);
        }
    }
}
