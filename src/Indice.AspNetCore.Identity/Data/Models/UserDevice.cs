﻿using System;
using Indice.Types;

namespace Indice.AspNetCore.Identity.Data.Models
{
    /// <summary>
    /// User devices representation.
    /// </summary>
    public class UserDevice
    {
        /// <summary>
        /// Constructs a new instance of <see cref="UserDevice"/> with a new Guid Id.
        /// </summary>
        public UserDevice() {
            Id = Guid.NewGuid();
        }

        /// <summary>
        /// The primary key.
        /// </summary>
        public Guid Id { get; set; }
        /// <summary>
        /// The user id related.
        /// </summary>
        public string UserId { get; set; }
        /// <summary>
        /// Device id.
        /// </summary>
        public Guid DeviceId { get; set; }
        /// <summary>
        /// Device operating system.
        /// </summary>
        public DevicePlatform DevicePlatform { get; set; }
        /// <summary>
        /// Device name.
        /// </summary>
        public string DeviceName { get; set; }
        /// <summary>
        /// The date this password was created.
        /// </summary>
        public DateTimeOffset DateCreated { get; set; }
        /// <summary>
        /// Flag that determines if push notifications are enabled for this device.
        /// </summary>
        public bool IsPushNotificationsEnabled { get; set; }
    }
}
