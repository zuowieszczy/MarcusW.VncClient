using Avalonia;
using Avalonia.Controls;
using Avalonia.Interactivity;
using Avalonia.Markup.Xaml;

namespace AvaloniaVncClient.Views.Dialogs
{
    public class EnterCreadentialsDialog : Window
    {
        private TextBox UsernameTextBox => this.FindControl<TextBox>("UsernameTextBox")!;

        private TextBox PasswordTextBox => this.FindControl<TextBox>("PasswordTextBox")!;

        public EnterCreadentialsDialog()
        {
            InitializeComponent();
        }

        private void InitializeComponent()
        {
            AvaloniaXamlLoader.Load(this);
            this.Loaded += (sender, e) => UsernameTextBox.Focus();
            UsernameTextBox.KeyBindings.Add(new Avalonia.Input.KeyBinding { Command = ReactiveUI.ReactiveCommand.Create(() => Close((UsernameTextBox.Text, PasswordTextBox.Text))), Gesture = new Avalonia.Input.KeyGesture(Avalonia.Input.Key.Enter) });
            UsernameTextBox.KeyBindings.Add(new Avalonia.Input.KeyBinding { Command = ReactiveUI.ReactiveCommand.Create(() => Close(null)), Gesture = new Avalonia.Input.KeyGesture(Avalonia.Input.Key.Escape) });
            PasswordTextBox.KeyBindings.Add(new Avalonia.Input.KeyBinding { Command = ReactiveUI.ReactiveCommand.Create(() => Close((UsernameTextBox.Text, PasswordTextBox.Text))), Gesture = new Avalonia.Input.KeyGesture(Avalonia.Input.Key.Enter) });
            PasswordTextBox.KeyBindings.Add(new Avalonia.Input.KeyBinding { Command = ReactiveUI.ReactiveCommand.Create(() => Close(null)), Gesture = new Avalonia.Input.KeyGesture(Avalonia.Input.Key.Escape) });
        }

        public void OnCancelClick(object sender, RoutedEventArgs e)
        {
            Close(null);
        }

        public void OnOkClick(object sender, RoutedEventArgs e)
        {
            Close((UsernameTextBox.Text, PasswordTextBox.Text));
        }
    }
}
