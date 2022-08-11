﻿namespace Indice.Features.Cases.Interfaces
{
    /// <summary>
    /// The JSON schema validator service.
    /// </summary>
    internal interface ISchemaValidator
    {
        /// <summary>
        /// Validate json data is valid against a json schema.
        /// </summary>
        /// <param name="schema">The json schema.</param>
        /// <param name="data">The json data.</param>
        bool IsValid(string schema, string data);
    }
}
