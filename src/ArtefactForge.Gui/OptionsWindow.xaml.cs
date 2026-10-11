using System.Windows;
using System.Windows.Controls;
using ArtefactForge.Core;

namespace ArtefactForge.Gui;

/// <summary>
/// Edits the declared options of every module that exposes any. Controls are built from the
/// declarations rather than hand-written per module, so a module that adds an option gets a
/// working editor with no code change here - the same reason modules are data in the first place.
/// </summary>
public partial class OptionsWindow : Window
{
    private readonly List<Section> _sections = [];

    private sealed class Section
    {
        public required ModuleDefinition Module { get; init; }
        public required Dictionary<string, Func<string>> Readers { get; init; }
        public required List<Action> Resets { get; init; }
        public required TextBlock Preview { get; init; }

        public Dictionary<string, string> Current()
        {
            var values = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (var (name, read) in Readers) values[name] = read();
            return values;
        }
    }

    /// <summary>Values per module, populated only when the dialog is accepted.</summary>
    public Dictionary<string, Dictionary<string, string>> Values { get; } = new(StringComparer.OrdinalIgnoreCase);

    public OptionsWindow(IEnumerable<ModuleItem> modules)
    {
        InitializeComponent();

        foreach (var item in modules.Where(m => m.Definition.Options.Count > 0))
            AddModule(item);

        if (_sections.Count == 0)
            OptionHost.Children.Add(new TextBlock { Text = "No module declares any options." });
    }

    private void AddModule(ModuleItem item)
    {
        var module = item.Definition;

        OptionHost.Children.Add(new TextBlock
        {
            Text = module.Name,
            FontSize = 17,
            Margin = new Thickness(0, _sections.Count == 0 ? 0 : 18, 0, 2)
        });
        OptionHost.Children.Add(Muted(new TextBlock
        {
            Text = module.Description,
            TextWrapping = TextWrapping.Wrap,
            Margin = new Thickness(0, 0, 0, 8)
        }));

        var preview = Muted(new TextBlock
        {
            FontFamily = new System.Windows.Media.FontFamily("Consolas"),
            TextWrapping = TextWrapping.Wrap
        });

        var section = new Section
        {
            Module = module,
            Readers = new Dictionary<string, Func<string>>(StringComparer.OrdinalIgnoreCase),
            Resets = [],
            Preview = preview
        };
        _sections.Add(section);

        var effective = ModuleOptions.Effective(module, item.OptionValues);
        foreach (var option in module.Options) AddOption(section, option, effective[option.Name]);

        var previewCard = Card(new Border
        {
            Margin = new Thickness(0, 2, 0, 0),
            Child = new StackPanel
            {
                Children =
                {
                    Muted(new TextBlock { Text = "Resulting flags", FontSize = 12 }),
                    preview
                }
            }
        });
        OptionHost.Children.Add(previewCard);

        Refresh(section);
    }

    private void AddOption(Section section, ModuleOption option, string value)
    {
        var rows = new StackPanel();
        rows.Children.Add(new TextBlock { Text = option.Name, FontSize = 14 });

        if (!string.IsNullOrWhiteSpace(option.Description))
            rows.Children.Add(Muted(new TextBlock
            {
                Text = option.Description,
                FontSize = 12,
                TextWrapping = TextWrapping.Wrap,
                Margin = new Thickness(0, 2, 0, 6)
            }));

        switch (option.Kind)
        {
            case OptionKind.Flag:
            {
                var box = new CheckBox { Content = "Enabled", IsChecked = IsOn(value) };
                box.Checked += (_, _) => Refresh(section);
                box.Unchecked += (_, _) => Refresh(section);
                rows.Children.Add(box);

                section.Readers[option.Name] = () => box.IsChecked == true ? "true" : "false";
                section.Resets.Add(() => box.IsChecked = IsOn(option.Default));
                break;
            }

            case OptionKind.Choice:
            {
                var box = new ComboBox { MinWidth = 260, HorizontalAlignment = HorizontalAlignment.Left };
                foreach (var choice in option.Choices)
                    // An empty choice is how an option is switched off; label it so it is pickable.
                    box.Items.Add(choice.Length == 0 ? NotSet : choice);

                box.SelectedIndex = IndexOf(option, value);
                box.SelectionChanged += (_, _) => Refresh(section);
                rows.Children.Add(box);

                section.Readers[option.Name] = () =>
                    box.SelectedItem as string is { } s && s != NotSet ? s : "";
                section.Resets.Add(() => box.SelectedIndex = IndexOf(option, option.Default));
                break;
            }

            default:
            {
                var box = new TextBox { Text = value, MinWidth = 380, HorizontalAlignment = HorizontalAlignment.Left };
                box.TextChanged += (_, _) => Refresh(section);
                rows.Children.Add(box);

                section.Readers[option.Name] = () => box.Text;
                section.Resets.Add(() => box.Text = option.Default);
                break;
            }
        }

        OptionHost.Children.Add(Card(new Border
        {
            Margin = new Thickness(0, 0, 0, 6),
            Child = rows
        }));
    }

    /// <summary>
    /// Shows the flags these settings actually produce. The command line is what ends up in the
    /// manifest, so seeing it before the run is worth more than any amount of description.
    /// </summary>
    private static void Refresh(Section section)
    {
        var expanded = ModuleOptions.Expand(section.Module, section.Current());
        section.Preview.Text = expanded.Length == 0 ? "(no flags added)" : expanded;
    }

    private static int IndexOf(ModuleOption option, string value)
    {
        for (var i = 0; i < option.Choices.Count; i++)
            if (string.Equals(option.Choices[i], value, StringComparison.OrdinalIgnoreCase))
                return i;
        return 0;
    }

    private static bool IsOn(string value) =>
        value.Equals("true", StringComparison.OrdinalIgnoreCase) || value == "1";

    private void OnReset(object sender, RoutedEventArgs e)
    {
        foreach (var section in _sections)
        {
            foreach (var reset in section.Resets) reset();
            Refresh(section);
        }
    }

    private void OnCancel(object sender, RoutedEventArgs e) => DialogResult = false;

    private void OnOk(object sender, RoutedEventArgs e)
    {
        foreach (var section in _sections)
        {
            var values = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (var (name, value) in section.Current())
            {
                if (!ModuleOptions.TryValidate(section.Module, name, value, out var error))
                {
                    // Only free text can reach here; the other controls cannot express a bad value.
                    MessageBox.Show(this, error, "ArtefactForge", MessageBoxButton.OK, MessageBoxImage.Warning);
                    return;
                }
                values[name] = value;
            }
            Values[section.Module.Name] = values;
        }

        DialogResult = true;
    }

    private const string NotSet = "(not set)";

    // Colours are resource references, not brushes, so the dialog follows a theme switch.

    private static TextBlock Muted(TextBlock text)
    {
        text.SetResourceReference(TextBlock.ForegroundProperty, "MutedBrush");
        return text;
    }

    private static Border Card(Border card)
    {
        card.SetResourceReference(Border.BackgroundProperty, "CardBrush");
        card.SetResourceReference(Border.BorderBrushProperty, "CardBorderBrush");
        card.BorderThickness = new Thickness(1);
        card.CornerRadius = new CornerRadius(6);
        card.Padding = new Thickness(10);
        return card;
    }
}
