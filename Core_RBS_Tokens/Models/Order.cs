using System.ComponentModel.DataAnnotations;
using System.Security.Principal;

namespace Core_RBS_Tokens.Models
{

    public class Item
    {
        public string? ItemName { get; set; }
        public double UnitPrice { get; set; }
    }

    public class ItemsDB:List<Item>
    {
        public ItemsDB()
        {
            Add(new Item { ItemName="Laptop", UnitPrice=123000 });
            Add(new Item { ItemName="Mobile", UnitPrice=23000 });
            Add(new Item { ItemName="Charger", UnitPrice=3000 });
            Add(new Item { ItemName="Charger Cable", UnitPrice=1200 });
            Add(new Item { ItemName="USB", UnitPrice=1000 });
            Add(new Item { ItemName="Power Bank", UnitPrice=10000 });
            Add(new Item { ItemName="Laptop Charger", UnitPrice=15000 });
            Add(new Item { ItemName="Screen", UnitPrice=8000 });
            Add(new Item { ItemName="Router", UnitPrice=3000 });
        }
    }
        

    public class Order
    {
        public int OrderId { get; set; }
        [Required(ErrorMessage ="Customer Name is Required")]
        public string? CustomerName { get; set; }
        [Required(ErrorMessage ="Item Name is Required")]
        public string? ItemName { get; set; }
        [Required(ErrorMessage = "Date is Required")]
        public DateOnly OrderedDate { get; set; }
        [Required(ErrorMessage ="Quantity is Required")]
        public int Quantity { get; set; }
        public double TotalPrice { get; set; }
        [Required(ErrorMessage ="Order Status is Mandatory")]
        public string? OrderStatus { get; set; }
        public string? CreatedBy { get; set; }
        public string? UpdatedBy { get; set; }
        public DateOnly UpdatedDate { get; set; }
        public bool IsApproved { get; set; }
        [Required(ErrorMessage ="Comments is required")]
        public string? Comments { get; set; }
    }
}
