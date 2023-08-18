﻿using System.Linq.Expressions;
using Indice.Features.Media.AspNetCore.Data.Models;

namespace Indice.Features.Media.AspNetCore.Stores.Abstractions;

/// <summary>A service that contains folder management related operations.</summary>
public interface IFolderStore
{
    /// <summary>Gets a folder by it's unique id.</summary>
    /// <param name="id">The id of the folder.</param>
    Task<DbFolder?> GetById(Guid id);
    /// <summary>Retreieves all folders.</summary>
    /// <param name="query">The query to limit the results.</param>
    Task<List<DbFolder>> GetList(Expression<Func<DbFolder, bool>>? query = null);
    /// <summary>Creates a new folder.</summary>
    /// <param name="folder">The data for the folder to create.</param>
    Task<Guid> Create(DbFolder folder);
    /// <summary>Updates an existing folder.</summary>
    /// <param name="folder">The data for the folder to update.</param>
    Task Update(DbFolder folder);
    /// <summary>Deletes an existing folder.</summary>
    /// <param name="id">The id of the folder.</param>
    Task Delete(Guid id);
    /// <summary>Marks the folders as deleted.</summary>
    /// <param name="ids">The ids of the folders to be marked as deleted.</param>
    Task MarkAsDeletedRange(List<Guid> ids);
}