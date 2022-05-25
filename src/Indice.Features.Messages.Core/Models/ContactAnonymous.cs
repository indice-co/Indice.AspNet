﻿using System;
using System.Collections.Generic;
using System.Text;

namespace Indice.Features.Messages.Core.Models
{
    /// <summary>
    /// An anonymous contact not originating from any the existing connected resolvers.
    /// </summary>
    public class ContactAnonymous
    {
        /// <summary>Contact salutation (Mr, Mrs etc).</summary>
        public string Salutation { get; set; }
        /// <summary>The first name.</summary>
        public string FirstName { get; set; }
        /// <summary>The last name.</summary>
        public string LastName { get; set; }
        /// <summary>The full name.</summary>
        public string FullName { get; set; }
        /// <summary>The email.</summary>
        public string Email { get; set; }
        /// <summary>The phone number.</summary>
        public string PhoneNumber { get; set; }

        /// <summary>
        /// Convert the anonymous contact to a concrete one
        /// </summary>
        /// <returns></returns>
        public Contact ToContact() => new() {
            Salutation = Salutation,
            Email = Email,
            FirstName = FirstName,
            LastName = LastName,
            FullName = FullName,
            PhoneNumber = PhoneNumber,
        };
    }
}
