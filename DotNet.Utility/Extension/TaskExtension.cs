using System;
using System.Threading;
using System.Threading.Tasks;

namespace DotNet.Utility
{
    public static class TaskExtension
    {
        public static void ForgetSafely(this Task task, Action<Exception> handleException)
        {
            task.ContinueWith(t =>
            {
                if (task.IsFaulted)
                {
                    handleException.Invoke(task.Exception);
                }
            });
        }

        public static async Task<TResult> TimeoutAfter<TResult>(this Task<TResult> task, TimeSpan timeout)
        {

            using (var timeoutCancellationTokenSource = new CancellationTokenSource())
            {

                var completedTask = await Task.WhenAny(task, Task.Delay(timeout, timeoutCancellationTokenSource.Token));
                if (completedTask == task)
                {
                    timeoutCancellationTokenSource.Cancel();
                    return await task;
                }
                else
                {
                    throw new TimeoutException("The operation has timed out.");
                }
            }
        }
    }
}
