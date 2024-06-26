using IdentityServer4.Events;
using IdentityServer4.Extensions;
using IdentityServer4.Services;
using IdentityServer4.Stores;
using Indice.AspNetCore.Filters;
using Indice.Features.Identity.UI.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace Indice.Features.Identity.UI.Pages;

/// <summary>Page model for the grants screen.</summary>
[Authorize]
[IdentityUI(typeof(GrantsModel))]
[SecurityHeaders]
public abstract class BaseGrantsModel : PageModel
{
    /// <summary>Creates a new instance of <see cref="BaseLoginModel"/> class.</summary>
    /// <param name="clients">Retrieval of client configuration.</param>
    /// <param name="events">Interface for the event service.</param>
    /// <param name="interaction">Provide services be used by the user interface to communicate with IdentityServer.</param>
    /// <param name="resources">Resource retrieval.</param>
    /// <exception cref="ArgumentNullException"></exception>
    public BaseGrantsModel(
        IClientStore clients,
        IEventService events,
        IIdentityServerInteractionService interaction,
        IResourceStore resources
    ) {
        Clients = clients ?? throw new ArgumentNullException(nameof(clients));
        Events = events ?? throw new ArgumentNullException(nameof(events));
        Interaction = interaction ?? throw new ArgumentNullException(nameof(interaction));
        Resources = resources ?? throw new ArgumentNullException(nameof(resources));
    }

    /// <summary>Retrieval of client configuration.</summary>
    protected IClientStore Clients { get; }
    /// <summary>Interface for the event service.</summary>
    protected IEventService Events { get; }
    /// <summary>Provide services be used by the user interface to communicate with IdentityServer.</summary>
    protected IIdentityServerInteractionService Interaction { get; }
    /// <summary>Resource retrieval.</summary>
    protected IResourceStore Resources { get; }

    /// <summary></summary>
    public GrantsViewModel View { get; set; } = new GrantsViewModel();

    /// <summary>Grants page GET handler.</summary>
    public virtual async Task<IActionResult> OnGetAsync() {
        View = await BuildViewModelAsync();
        return Page();
    }

    /// <summary>Grants page GET handler.</summary>
    public virtual async Task<IActionResult> OnPostRevokeAsync(string clientId) {
        await Interaction.RevokeUserConsentAsync(clientId);
        await Events.RaiseAsync(new GrantsRevokedEvent(User.GetSubjectId(), clientId));
        return RedirectToPage("/Grants");
    }

    private async Task<GrantsViewModel> BuildViewModelAsync() {
        var grants = await Interaction.GetAllUserGrantsAsync();
        var list = new List<GrantModel>();
        foreach (var grant in grants) {
            var client = await Clients.FindClientByIdAsync(grant.ClientId);
            if (client != null) {
                var resources = await Resources.FindResourcesByScopeAsync(grant.Scopes);
                var item = new GrantModel {
                    ApiGrantNames = resources.ApiScopes.Select(x => x.DisplayName ?? x.Name).ToArray(),
                    ClientId = client.ClientId,
                    ClientLogoUrl = client.LogoUri,
                    ClientName = client.ClientName ?? client.ClientId,
                    ClientUrl = client.ClientUri,
                    Created = grant.CreationTime,
                    Description = grant.Description,
                    Expires = grant.Expiration,
                    IdentityGrantNames = resources.IdentityResources.Select(x => x.DisplayName ?? x.Name).ToArray()
                };
                list.Add(item);
            }
        }
        return new GrantsViewModel {
            Grants = list
        };
    }
}

internal class GrantsModel : BaseGrantsModel
{
    public GrantsModel(
        IClientStore clients,
        IEventService events,
        IIdentityServerInteractionService interaction,
        IResourceStore resources
    ) : base(clients, events, interaction, resources) { }
}
