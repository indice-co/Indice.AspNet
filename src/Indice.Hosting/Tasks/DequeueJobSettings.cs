﻿namespace Indice.Hosting.Tasks;

/// <summary>Contains meta-data about a job to execute.</summary>
internal class DequeueJobSettings
{
    /// <summary>Creates a new instance of <see cref="DequeueJobSettings"/>.</summary>
    /// <param name="jobHandlerType">The CLR type of the job's handler.</param>
    /// <param name="workItemType">The CLR type of the job's work item.</param>
    /// <param name="jobName">The name of the job.</param>
    /// <param name="pollingInterval">The time interval between two attempts to dequeue new items. In milliseconds.</param>
    /// <param name="backoffThreshold">The maximum time interval between two attempts to dequeue new items. In milliseconds.</param>
    /// <param name="cleanUpInterval">Cleanup up the queue every interval seconds.</param>
    /// <param name="cleanUpBatchSize">Cleanup every items.</param>
    /// <param name="instanceCount">Number of concurrent instances.</param>
    public DequeueJobSettings(Type jobHandlerType, Type workItemType, string jobName, double pollingInterval, double backoffThreshold, int cleanUpInterval, int cleanUpBatchSize, int instanceCount) {
        JobHandlerType = jobHandlerType;
        WorkItemType = workItemType;
        Name = jobName;
        PollingInterval = pollingInterval;
        MaxPollingInterval = backoffThreshold;
        CleanupInterval = cleanUpInterval;
        CleanupBatchSize = cleanUpBatchSize;
        InstanceCount = instanceCount;
    }

    /// <summary>The CLR type of the job's handler.</summary>
    public Type JobHandlerType { get; }
    /// <summary>The CLR type of the job's work item.</summary>
    public Type WorkItemType { get; }
    /// <summary>The name of the job.</summary>
    public string Name { get; set; }
    /// <summary>The time interval between two attempts to dequeue new items. Measured in milliseconds</summary>
    public double PollingInterval { get; set; } = 300;
    /// <summary>The maximum time interval between two attempts to dequeue new items. Measured in milliseconds</summary>
    public double MaxPollingInterval { get; set; } = 5000;
    /// <summary>The concurrent instance count.</summary>
    public int InstanceCount { get; set; } = 10;
    /// <summary>Cleanup interval in seconds.</summary>
    public int CleanupInterval { get; set; } = 3600;
    /// <summary>Cleanup batch size</summary>
    public int CleanupBatchSize { get; set; } = 100;
}
