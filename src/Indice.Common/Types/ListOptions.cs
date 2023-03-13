﻿namespace Indice.Types;

/// <summary>List parameters used to navigate through collections. Contains parameters such as sort, search, page number and page size.</summary>
public class ListOptions
{
    private readonly Dictionary<string, string> SortRedirects;
    private int _page;
    private int _size;

    /// <summary>Creates instance with default parameters.</summary>
    public ListOptions() {
        Page = 1;
        Size = 100;
        Sort = string.Empty;
        SortRedirects = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
    }

    /// <summary>The current page of the list. Default is 1.</summary>
    public int? Page { get => _page; set => _page = value ?? 1; }
    /// <summary>The size of the list. Default is 100.</summary>
    public int? Size { get => _size; set => _size = value ?? 100; }
    /// <summary>The property name used to sort the list.</summary>
    public string Sort { get; set; }
    /// <summary>A search term used to limit the results of the list.</summary>
    public string Search { get; set; }

    /// <summary>Retrieves the number of pages for a total of <paramref name="count"/> results.</summary>
    /// <param name="count">The number of results</param>
    public int GetPagesFor(int count) => Size > 0 ? (int)Math.Ceiling(count / (double)Size) : 0;

    /// <summary>
    /// Break the <see cref="Sort"/> parameter into multiple sort by clauses. 
    /// Takes the Name-,Date+ etc... and enumerates it.
    /// </summary>
    public IEnumerable<SortByClause> GetSortings() {
        var list = (Sort ?? string.Empty).Split(',');
        foreach (var item in list) {
            if (string.IsNullOrWhiteSpace(item)) {
                continue;
            }
            var sortBy = SortByClause.Parse(item);
            if (SortRedirects.ContainsKey(sortBy.Path)) {
                sortBy = new SortByClause(SortRedirects[sortBy.Path], sortBy.Direction, sortBy.DataType);
            }
            yield return sortBy;
        }
    }

    /// <summary>
    /// Add a <see cref="SortByClause"/> to the current <seealso cref="Sort"/> string. 
    /// The clauses are searched by their <seealso cref="SortByClause.Path"/>. 
    /// If a clause with the same path is found it will be updated. 
    /// </summary>
    /// <param name="sort">The sort clause.</param>
    public void AddSort(SortByClause sort) {
        if (string.IsNullOrWhiteSpace(Sort)) {
            Sort = sort;
        } else {
            var parts = (Sort ?? string.Empty).Split(',');
            var paths = parts.Select(x => ((SortByClause)x).Path).ToList();
            var index = paths.IndexOf(sort.Path);
            if (index > -1) {
                parts[index] = sort;
                Sort = string.Join(",", parts);
            } else {
                Sort = string.Join(",", parts.Concat(new[] { (string)sort }).ToArray());
            }
        }
    }
    /// <summary>Remove a <see cref="SortByClause"/> to the current <seealso cref="Sort"/> string. The clauses are searched by their <seealso cref="SortByClause.Path"/>.</summary>
    /// <param name="sort">The sort clause.</param>
    public void RemoveSort(SortByClause sort) {
        var parts = (Sort ?? string.Empty).Split(',');
        Sort = string.Join(",", parts.Where(x => ((SortByClause)x).Path != sort.Path).ToArray());
    }

    /// <summary>
    /// Adds a redirect mapping in order to handle server side scenarios where the sort field property path 
    /// could be in a different location than the display member path. This redirects an incoming property/field path to the one 
    /// corresponding to the underlying storage provider model. Usually if the underlying storage provider is EF or dapper 
    /// it will map to DataBase model property path or column name respectfully. 
    /// </summary>
    /// <param name="from">Client side member path</param>
    /// <param name="to">Server side member path</param>
    public void AddSortRedirect(string from, string to) => SortRedirects.Add(from, to);

    /// <summary>Convert all the list parameters into a <see cref="Dictionary{TKey, TValue}"/>.</summary>
    public virtual IDictionary<string, object> ToDictionary() {
        var dictionary = new Dictionary<string, object>(StringComparer.OrdinalIgnoreCase) {
            { nameof(Page).ToLower(), Page.ToString() },
            { nameof(Size).ToLower(), Size.ToString() },
        };
        if (!string.IsNullOrWhiteSpace(Sort)) {
            dictionary.Add(nameof(Sort).ToLower(), Sort);
        }
        if (!string.IsNullOrWhiteSpace(Search)) {
            dictionary.Add(nameof(Search).ToLower(), Search);
        }
        return dictionary;
    }
}

/// <summary>A variant of list options that allows for the use of a custom filter model. More advanced than plain a search text.</summary>
/// <typeparam name="TFilter">The type of filter.</typeparam>
public class ListOptions<TFilter> : ListOptions where TFilter : class, new()
{
    /// <summary>
    /// Creates instance with default parameters 
    /// and initializes the Filter using the default constructor. 
    /// </summary>
    public ListOptions() : base() => Filter = new TFilter();

    /// <summary>The custom filter options.</summary>
    public TFilter Filter { get; set; }

    /// <summary>
    /// Converts the options to a dictionary of key value pairs suitable for use 
    /// as Route parameters and / or query string parameters depending on client or server use.
    /// </summary>
    /// <returns></returns>
    public override IDictionary<string, object> ToDictionary() {
        var dictionary = base.ToDictionary();
        return dictionary.Merge(Filter, typeof(TFilter), "filter.");
    }
}
