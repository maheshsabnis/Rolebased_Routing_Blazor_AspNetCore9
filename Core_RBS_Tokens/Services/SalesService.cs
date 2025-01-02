using Core_RBS_Tokens.Models;
using Microsoft.EntityFrameworkCore;

namespace Core_RBS_Tokens.Services
{
    public class SalesService(SalesContext context)
    {
        Item item = new Item();
        ItemsDB items = new ItemsDB();
        ResponseObject<Order> response = new ResponseObject<Order>();

        public async Task<ResponseObject<Order>> GetAsync()
        {
            try
            {
                response.Records = await context.Orders.ToListAsync();
                response.Message = "Orders Read Successfully";
                response.StatusCode = 200;
            }
            catch (Exception ex)
            {
                throw ex;
            }
            return response;
        }
        public async Task<ResponseObject<Order>> GetAsync(int id)
        {
            try
            {
                response.Record = await context.Orders.FindAsync(id);
                response.Message = $"Order Based on id: {id} is Read Successfully";
                response.StatusCode = 200;
            }
            catch (Exception ex)
            {
                throw ex;
            }
            return response;
        }

        public async Task<ResponseObject<Order>> SaveOdreAsync(Order order)
        {
            try
            {
                // Calculate the TotalPrice for the Order based on the Quantity and the
                // UnitPrice of the Item
                var unitprice = items.Where(i => i.ItemName.Trim() == order.ItemName.Trim()).FirstOrDefault().UnitPrice;
                order.TotalPrice = order.Quantity * unitprice;
                order.OrderedDate = DateOnly.FromDateTime(DateTime.Now);
                order.OrderStatus = "New Order";
                var entity = await context.Orders.AddAsync(order);
                await context.SaveChangesAsync();
                response.Message = $"Order is placed Successfully";
                response.StatusCode = 201;
            }
            catch (Exception ex)
            {
                throw ex;
            }
            return response;
        }

        public async Task<ResponseObject<Order>> UpdateOdreAsync(int id, Order order)
        {
            try
            {
                Order? orderToUpdate = await context.Orders.FindAsync(id);
                orderToUpdate.ItemName = order.ItemName;
                order.Quantity = orderToUpdate.Quantity;
                order.OrderStatus = orderToUpdate.OrderStatus;
                orderToUpdate.UpdatedBy = order.UpdatedBy;
                order.UpdatedDate = DateOnly.FromDateTime(DateTime.Now);
                 order.OrderStatus = "Updated";

                // Calculate the TotalPrice for the Order based on the Quantity and the
                // UnitPrice of the Item
                var unitprice = items.Where(i => i.ItemName.Trim() == order.ItemName.Trim()).FirstOrDefault().UnitPrice;
                order.TotalPrice = order.Quantity * unitprice;
                var entity = await context.Orders.AddAsync(order);
                await context.SaveChangesAsync();
                response.Message = $"Order is updated Successfully";
                response.StatusCode = 201;
            }
            catch (Exception ex)
            {
                throw ex;
            }
            return response;
        }
        public async Task<ResponseObject<Order>> DeleteOrderAsync(int id)
        {
            try
            {
                Order? orderToDelete = await context.Orders.FindAsync(id);
                context.Orders.Remove(orderToDelete);
                await context.SaveChangesAsync();
                  response.Message = $"Order is deleted Successfully";
                response.StatusCode = 201;
            }
            catch (Exception ex)
            {

                throw ex;
            }
            return response;
        }

        public async Task<ResponseObject<Order>> ApproveRejectOrderAsync(int id, Order order)
        {
            try
            {
                Order? orderToProcess = await context.Orders.FindAsync(id);
                orderToProcess.IsApproved = order.IsApproved;
                orderToProcess.Comments = order.Comments;
                await context.SaveChangesAsync();

                if(orderToProcess.IsApproved)
                { 
                   response.Message = $"Order {id} is apporved successfully";
                }
                else
                { 
                    response.Message = $"Order {id} is rejected ";
                }
                response.StatusCode = 201;
            }
            catch (Exception ex)
            {
                throw ex;
            }
            return response;
        }
    }
}
