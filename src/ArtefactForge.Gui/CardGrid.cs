using System.Windows;
using System.Windows.Controls;

namespace ArtefactForge.Gui;

/// <summary>
/// Lays cards out left to right in equal columns, each row as tall as its own tallest card and
/// each card top-aligned at its own height. UniformGrid makes every row as tall as the tallest card
/// anywhere, which leaves rows of short cards mostly empty; WrapPanel cannot share the width out
/// evenly. Fewer columns are used when they would come out narrower than MinColumnWidth.
/// </summary>
public sealed class CardGrid : Panel
{
    public static readonly DependencyProperty ColumnsProperty = DependencyProperty.Register(
        nameof(Columns), typeof(int), typeof(CardGrid),
        new FrameworkPropertyMetadata(4, FrameworkPropertyMetadataOptions.AffectsMeasure));

    public static readonly DependencyProperty MinColumnWidthProperty = DependencyProperty.Register(
        nameof(MinColumnWidth), typeof(double), typeof(CardGrid),
        new FrameworkPropertyMetadata(240.0, FrameworkPropertyMetadataOptions.AffectsMeasure));

    public static readonly DependencyProperty SpacingProperty = DependencyProperty.Register(
        nameof(Spacing), typeof(double), typeof(CardGrid),
        new FrameworkPropertyMetadata(12.0, FrameworkPropertyMetadataOptions.AffectsMeasure));

    public int Columns
    {
        get => (int)GetValue(ColumnsProperty);
        set => SetValue(ColumnsProperty, value);
    }

    public double MinColumnWidth
    {
        get => (double)GetValue(MinColumnWidthProperty);
        set => SetValue(MinColumnWidthProperty, value);
    }

    public double Spacing
    {
        get => (double)GetValue(SpacingProperty);
        set => SetValue(SpacingProperty, value);
    }

    private int ColumnCount(double width)
    {
        if (double.IsInfinity(width)) return Math.Max(1, Columns);
        var fit = (int)((width + Spacing) / (MinColumnWidth + Spacing));
        return Math.Clamp(fit, 1, Math.Max(1, Columns));
    }

    private double ColumnWidth(double width, int columns) =>
        double.IsInfinity(width) ? MinColumnWidth : Math.Max(0, (width - Spacing * (columns - 1)) / columns);

    protected override Size MeasureOverride(Size availableSize)
    {
        var columns = ColumnCount(availableSize.Width);
        var width = ColumnWidth(availableSize.Width, columns);
        foreach (UIElement child in InternalChildren)
            child.Measure(new Size(width, double.PositiveInfinity));

        var height = RowHeights(columns).Sum() + Spacing * Math.Max(0, RowCount(columns) - 1);
        var total = double.IsInfinity(availableSize.Width)
            ? width * columns + Spacing * (columns - 1)
            : availableSize.Width;
        return new Size(total, height);
    }

    protected override Size ArrangeOverride(Size finalSize)
    {
        var columns = ColumnCount(finalSize.Width);
        var width = ColumnWidth(finalSize.Width, columns);
        var rows = RowHeights(columns);

        var y = 0.0;
        for (var i = 0; i < InternalChildren.Count; i++)
        {
            var (row, column) = Math.DivRem(i, columns);
            if (column == 0 && row > 0) y += rows[row - 1] + Spacing;
            var child = InternalChildren[i];
            child.Arrange(new Rect(column * (width + Spacing), y, width, child.DesiredSize.Height));
        }
        return finalSize;
    }

    private int RowCount(int columns) => (InternalChildren.Count + columns - 1) / columns;

    private List<double> RowHeights(int columns)
    {
        var rows = new List<double>();
        for (var i = 0; i < InternalChildren.Count; i++)
        {
            if (i % columns == 0) rows.Add(0);
            rows[^1] = Math.Max(rows[^1], InternalChildren[i].DesiredSize.Height);
        }
        return rows;
    }
}
