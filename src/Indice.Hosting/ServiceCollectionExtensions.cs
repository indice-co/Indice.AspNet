﻿using System;
using Indice.Hosting;
using Indice.Hosting.Tasks;
using Indice.Hosting.Tasks.Data;
using Indice.Services;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Quartz;
using Quartz.Impl;
using Quartz.Spi;

namespace Microsoft.Extensions.DependencyInjection
{
    /// <summary>
    /// Extension methods on <see cref="IServiceCollection"/> that help register required services for background task processing.
    /// </summary>
    public static class ServiceCollectionExtensions
    {
        /// <summary>
        /// Registers a hosted service that manages and configures the lifetime of background tasks.
        /// </summary>
        /// <param name="services">Specifies the contract for a collection of service descriptors.</param>
        /// <param name="configureAction">The delegate used to configure the worker host options.</param>
        /// <returns>The <see cref="WorkerHostBuilder"/> used to configure the worker host.</returns>
        public static WorkerHostBuilder AddWorkerHost(this IServiceCollection services, Action<WorkerHostOptions> configureAction) {
            services.AddSingleton<ISchedulerFactory, StdSchedulerFactory>();
            services.AddSingleton<IJobFactory, JobFactory>();
            services.AddSingleton<TaskHandlerActivator>();
            services.AddSingleton<QuartzJobRunner>();
            services.AddHostedService<WorkerHostedService>();
            var workerHostOptions = new WorkerHostOptions(services);
            configureAction.Invoke(workerHostOptions);
            return new WorkerHostBuilder(services, workerHostOptions.WorkItemQueueType);
        }

        /// <summary>
        /// Uses Azure Storage service as the store for distributed locking.
        /// </summary>
        /// <param name="options">The <see cref="WorkerHostOptions"/> used to configure locking and queue persistence.</param>
        /// <returns>The <see cref="WorkerHostOptions"/> used to configure locking and queue persistence.</returns>
        public static WorkerHostOptions UseAzureStorageLock(this WorkerHostOptions options) => options.UseLock<LockManagerAzure>();

        /// <summary>
        /// Manages access to queues using an in-memory mechanism. Not suitable for distributed scenarios.
        /// </summary>
        /// <param name="options">The <see cref="WorkerHostOptions"/> used to configure locking and queue persistence.</param>
        /// <returns>The <see cref="WorkerHostOptions"/> used to configure locking and queue persistence.</returns>
        public static WorkerHostOptions UseInMemoryLock(this WorkerHostOptions options) => options.UseLock<LockManagerInMemory>();

        /// <summary>
        /// Registers an implementation of <see cref="ILockManager"/> which is used for distributed locking.
        /// </summary>
        /// <typeparam name="TLockManager">The concrete type of <see cref="ILockManager"/> to use.</typeparam>
        /// <param name="options">The <see cref="WorkerHostOptions"/> used to configure locking and queue persistence.</param>
        /// <returns>The <see cref="WorkerHostOptions"/> used to configure locking and queue persistence.</returns>
        public static WorkerHostOptions UseLock<TLockManager>(this WorkerHostOptions options) where TLockManager : ILockManager {
            options.Services.TryAddSingleton(typeof(ILockManager), typeof(TLockManager));
            return options;
        }

        /// <summary>
        /// Uses an in-memory storage mechanism in order to manage queue items.
        /// </summary>
        /// <param name="options">The <see cref="WorkerHostOptions"/> used to configure locking and queue persistence.</param>
        /// <returns>The <see cref="WorkerHostOptions"/> used to configure locking and queue persistence.</returns>
        public static WorkerHostOptions UseInMemoryStorage(this WorkerHostOptions options) =>
            throw new NotImplementedException();//options.UseStorage(typeof(WorkItemQueueInMemory<>));

        /// <summary>
        /// Uses a SQL Server database table, in order to manage queue items.
        /// </summary>
        /// <param name="options">The <see cref="WorkerHostOptions"/> used to configure locking and queue persistence.</param>
        /// <param name="configureAction">The delegate used to configure the SQL Server table that contains the background jobs.</param>
        /// <returns>The <see cref="WorkerHostOptions"/> used to configure locking and queue persistence.</returns>
        public static WorkerHostOptions UseSqlServerStorage(this WorkerHostOptions options, Action<DbContextOptionsBuilder> configureAction = null) {
            if (configureAction != null) {
                options.Services.AddDbContext<TaskDbContext>(configureAction);
            } else {
                options.Services.AddDbContext<TaskDbContext>((sp, opt) => {
                    opt.UseSqlServer(sp.GetService<IConfiguration>().GetConnectionString("WorkerDb"));
                });
            }
            return options.UseStorage(typeof(EFMessageQueue<>));
        }

        /// <summary>
        /// Registers a job that will be processed by the worker host. Usually followed by a <see cref="WithQueueTrigger{TWorkItem}(TaskTriggerBuilder, Action{QueueOptions})"/> call to configure the way that a job is triggered.
        /// </summary>
        /// <typeparam name="TJobHandler">The type of the class that will handle the job. Must have a process function.</typeparam>
        /// <param name="builder">The <see cref="WorkerHostBuilder"/> used to configure the worker host.</param>
        /// <returns>The <see cref="TaskTriggerBuilder"/> used to configure the way that a job is triggered.</returns>
        public static TaskTriggerBuilder AddJob<TJobHandler>(this WorkerHostBuilder builder) where TJobHandler : class {
            return new TaskTriggerBuilder(builder.Services, typeof(TJobHandler), builder.WorkItemQueueType);
        }
            

        /// <summary>
        /// Specifies that the configured job will be triggered by an item inserted to the a queue.
        /// </summary>
        /// <param name="builder">The <see cref="TaskTriggerBuilder"/> used to configure the way that a job is triggered.</param>
        /// <param name="configureAction">The delegate used to configure the queue options.</param>
        /// <returns>The <see cref="WorkerHostBuilder"/> used to configure the worker host.</returns>
        public static WorkerHostBuilder WithQueueTrigger<TWorkItem>(this TaskTriggerBuilder builder, Action<QueueOptions> configureAction = null) where TWorkItem : class {
            var options = new QueueOptions(builder.Services);
            configureAction?.Invoke(options);
            options.Services.AddTransient(builder.JobHandlerType);
            options.Services.AddTransient(typeof(IQueueNameResolver<>).MakeGenericType(typeof(TWorkItem)), sp => Activator.CreateInstance(typeof(DefaultQueueNameResolver<>).MakeGenericType(typeof(TWorkItem)), new object[] { options }));
            options.Services.AddTransient(typeof(IMessageQueue<>).MakeGenericType(typeof(TWorkItem)), builder.QueueType.MakeGenericType(typeof(TWorkItem)));
            options.Services.AddTransient(typeof(DequeueJob<>).MakeGenericType(typeof(TWorkItem)));
            options.Services.AddTransient(serviceProvider => new DequeueJobSettings(builder.JobHandlerType, typeof(TWorkItem), serviceProvider.GetService<IQueueNameResolver<TWorkItem>>().Resolve(), options.PollingInterval, options.MaxPollingInterval, options.InstanceCount));
            return new WorkerHostBuilder(options.Services, builder.QueueType);
        }

        /// <summary>
        /// Specifies that the configured job will be triggered by an item inserted to the a queue.
        /// </summary>
        /// <param name="builder">The <see cref="TaskTriggerBuilder"/> used to configure the way that a job is triggered.</param>
        /// <param name="cronExpression">Corn expressinon</param>
        /// <param name="configureAction">The delegate used to configure the queue options.</param>
        /// <returns>The <see cref="WorkerHostBuilder"/> used to configure the worker host.</returns>
        public static WorkerHostBuilder WithScheduleTrigger(this TaskTriggerBuilder builder, string cronExpression, Action<ScheduleOptions> configureAction = null) {
            if (string.IsNullOrWhiteSpace(cronExpression)) {
                throw new ArgumentException($"'{nameof(cronExpression)}' cannot be null or whitespace", nameof(cronExpression));
            }
            var options = new ScheduleOptions(builder.Services);
            options.CronExpression = cronExpression;
            configureAction?.Invoke(options);
            options.Services.AddTransient(builder.JobHandlerType);
            options.Services.AddTransient(typeof(ScheduledJob<>).MakeGenericType(builder.JobHandlerType));
            options.Services.AddTransient(serviceProvider => new ScheduledJobSettings(builder.JobHandlerType, cronExpression, options.Group, options.Description));
            return new WorkerHostBuilder(options.Services);
        }

        /// <summary>
        /// Specifies that the configured job will be triggered by an item inserted to the a queue.
        /// </summary>
        /// <typeparam name="TWorkItem"></typeparam>
        /// <param name="builder">The <see cref="TaskTriggerBuilder"/> used to configure the way that a job is triggered.</param>
        /// <param name="queueName">The name of the queue.</param>
        /// <param name="pollingIntervalInSeconds">Specifies the time interval between two attempts to dequeue new items.</param>
        /// <returns>The <see cref="WorkerHostBuilder"/> used to configure the worker host.</returns>
        public static WorkerHostBuilder WithQueueTrigger<TWorkItem>(this TaskTriggerBuilder builder, string queueName, int pollingIntervalInSeconds) where TWorkItem : class =>
            builder.WithQueueTrigger<TWorkItem>(options => new QueueOptions(builder.Services) {
                QueueName = queueName,
                PollingInterval = pollingIntervalInSeconds
            });

        private static WorkerHostOptions UseStorage(this WorkerHostOptions options, Type workItemQueueType) {
            options.WorkItemQueueType = workItemQueueType;
            return options;
        }
    }
}
