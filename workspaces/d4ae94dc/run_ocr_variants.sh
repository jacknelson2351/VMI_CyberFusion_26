#!/bin/bash
mkdir -p ocr_results
img=road_1.png
# sizes and enhancements
sizes=(1 2 4)
psms=(3 6 11)
idx=0
for s in "${sizes[@]}"; do
  out=ocr_results/road_scaled_${s}x.png
  convert "$img" -colorspace Gray -brightness-contrast 10x10 -resize "$((s*100))%" -unsharp 0x1 "$out"
  for p in "${psms[@]}"; do
    t_out=ocr_results/ocr_scaled_${s}x_psm${p}.txt
    tesseract "$out" "$t_out" -l eng --psm $p > /dev/null 2>&1 || true
    # tesseract appends .txt automatically, ensure consistent naming
    if [ -f "$t_out.txt" ]; then mv "$t_out.txt" "$t_out"; fi
  done
done
# Also try adaptive threshold and edge detect to highlight signs
convert "$img" -colorspace Gray -resize 200% -normalize -threshold 60% ocr_results/road_thresh.png
for p in "${psms[@]}"; do
  t_out=ocr_results/ocr_thresh_psm${p}.txt
  tesseract ocr_results/road_thresh.png "$t_out" -l eng --psm $p > /dev/null 2>&1 || true
  if [ -f "$t_out.txt" ]; then mv "$t_out.txt" "$t_out"; fi
done

echo "Done"
ls -l ocr_results
