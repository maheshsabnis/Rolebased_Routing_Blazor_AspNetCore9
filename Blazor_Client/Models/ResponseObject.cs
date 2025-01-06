namespace Blazor_Client.Models
{
    public class ResponseObject<TEntity> where TEntity : class
    {
        public IEnumerable<TEntity>? Records { get; set; }
        public TEntity? Record { get; set; }
        public string? Message { get; set; }
        public int StatusCode { get; set; }
    }
}
