﻿using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using Indice.Types;

namespace Indice.AspNetCore.Identity.Api.Models
{
    /// <summary>
    /// Register a device for push notifications
    /// </summary>
    public class RegisterDeviceRequest
    {
        /// <summary>
        /// The deviceId to register for push notifications.
        /// </summary>
        [Required]
        public Guid DeviceId { get; set; }
        /// <summary>
        /// Platform Notification Service (pns) obtained from client platform.
        /// </summary>
        [Required(AllowEmptyStrings = false)]
        public string PnsHandle { get; set; }
        /// <summary>
        /// Device name.
        /// </summary>
        [Required(AllowEmptyStrings = false), MaxLength(250)]
        public string DeviceName { get; set; }
        /// <summary>
        /// Client device platform.
        /// </summary>
        [Required]
        public DevicePlatform DevicePlatform { get; set; }
        /// <summary>
        /// Tags are used to route notifications to the correct set of device handles.
        /// </summary>
        public List<string> Tags { get; set; }
    }
}
