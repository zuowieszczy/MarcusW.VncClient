using Avalonia;
using Avalonia.Controls;
using Avalonia.Interactivity;
using Avalonia.Markup.Xaml;

namespace AvaloniaVncClient.Views.Dialogs
{
    public class EnterPasswordDialog : Window
    {
        private TextBox PasswordTextBox => this.FindControl<TextBox>("PasswordTextBox");

        public EnterPasswordDialog()
        {
            InitializeComponent();
        }

        private void InitializeComponent()
        {
            AvaloniaXamlLoader.Load(this);
            this.Loaded += (sender, e) => PasswordTextBox.Focus();
            PasswordTextBox.KeyBindings.Add(new Avalonia.Input.KeyBinding { Command = ReactiveUI.ReactiveCommand.Create(() => Close(PasswordTextBox.Text)), Gesture = new Avalonia.Input.KeyGesture(Avalonia.Input.Key.Enter) });
            PasswordTextBox.KeyBindings.Add(new Avalonia.Input.KeyBinding { Command = ReactiveUI.ReactiveCommand.Create(() => Close(null)), Gesture = new Avalonia.Input.KeyGesture(Avalonia.Input.Key.Escape) });
        }

        public void OnCancelClick(object sender, RoutedEventArgs e)
        {
            Close(null);
        }

        public void OnOkClick(object sender, RoutedEventArgs e)
        {
            Close(PasswordTextBox.Text);
        }
    }
}
