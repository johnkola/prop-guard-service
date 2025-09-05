'use client';

import { ChevronLeft, ChevronRight, ChevronsLeft, ChevronsRight } from 'lucide-react';

interface PaginationProps {
    currentPage: number;
    totalPages: number;
    totalItems: number;
    itemsPerPage: number;
    onPageChange: (page: number) => void;
    onItemsPerPageChange?: (itemsPerPage: number) => void;
    showItemsPerPage?: boolean;
    itemsPerPageOptions?: number[];
}

export default function Pagination({
    currentPage,
    totalPages,
    totalItems,
    itemsPerPage,
    onPageChange,
    onItemsPerPageChange,
    showItemsPerPage = true,
    itemsPerPageOptions = [10, 20, 50, 100]
}: PaginationProps) {
    // Calculate the range of items being displayed
    const startItem = totalItems === 0 ? 0 : (currentPage - 1) * itemsPerPage + 1;
    const endItem = Math.min(currentPage * itemsPerPage, totalItems);

    // Generate page numbers to display
    const getPageNumbers = () => {
        const pages: (number | string)[] = [];
        const maxButtons = 7; // Maximum number of page buttons to show
        
        if (totalPages <= maxButtons) {
            // Show all pages if total is less than max
            for (let i = 1; i <= totalPages; i++) {
                pages.push(i);
            }
        } else {
            // Always show first page
            pages.push(1);
            
            if (currentPage <= 3) {
                // Near the beginning
                for (let i = 2; i <= 5; i++) {
                    pages.push(i);
                }
                pages.push('...');
                pages.push(totalPages);
            } else if (currentPage >= totalPages - 2) {
                // Near the end
                pages.push('...');
                for (let i = totalPages - 4; i <= totalPages; i++) {
                    pages.push(i);
                }
            } else {
                // In the middle
                pages.push('...');
                for (let i = currentPage - 1; i <= currentPage + 1; i++) {
                    pages.push(i);
                }
                pages.push('...');
                pages.push(totalPages);
            }
        }
        
        return pages;
    };

    const handlePageClick = (page: number | string) => {
        if (typeof page === 'number' && page !== currentPage) {
            onPageChange(page);
        }
    };

    const handleItemsPerPageChange = (e: React.ChangeEvent<HTMLSelectElement>) => {
        const newItemsPerPage = parseInt(e.target.value);
        if (onItemsPerPageChange) {
            onItemsPerPageChange(newItemsPerPage);
            // Reset to first page when changing items per page
            onPageChange(1);
        }
    };

    if (totalPages <= 1 && !showItemsPerPage) {
        return null; // Don't show pagination if there's only one page
    }

    return (
        <div className="flex flex-col sm:flex-row items-center justify-between gap-4 py-4">
            {/* Items per page selector and info */}
            <div className="flex items-center gap-4">
                {showItemsPerPage && onItemsPerPageChange && (
                    <div className="flex items-center gap-2">
                        <span className="text-sm text-base-content/70">Show</span>
                        <select
                            className="select select-bordered select-sm"
                            value={itemsPerPage}
                            onChange={handleItemsPerPageChange}
                        >
                            {itemsPerPageOptions.map(option => (
                                <option key={option} value={option}>
                                    {option}
                                </option>
                            ))}
                        </select>
                        <span className="text-sm text-base-content/70">per page</span>
                    </div>
                )}
                
                {/* Items info */}
                <div className="text-sm text-base-content/70">
                    {totalItems === 0 ? (
                        'No items'
                    ) : (
                        <>
                            Showing <span className="font-semibold">{startItem}</span> to{' '}
                            <span className="font-semibold">{endItem}</span> of{' '}
                            <span className="font-semibold">{totalItems}</span> items
                        </>
                    )}
                </div>
            </div>

            {/* Page navigation */}
            {totalPages > 1 && (
                <div className="flex items-center gap-1">
                    {/* First page button */}
                    <button
                        className="btn btn-ghost btn-sm"
                        onClick={() => onPageChange(1)}
                        disabled={currentPage === 1}
                        title="First page"
                    >
                        <ChevronsLeft className="w-4 h-4" />
                    </button>

                    {/* Previous page button */}
                    <button
                        className="btn btn-ghost btn-sm"
                        onClick={() => onPageChange(currentPage - 1)}
                        disabled={currentPage === 1}
                        title="Previous page"
                    >
                        <ChevronLeft className="w-4 h-4" />
                    </button>

                    {/* Page numbers */}
                    <div className="flex items-center gap-1">
                        {getPageNumbers().map((page, index) => (
                            <button
                                key={index}
                                className={`btn btn-sm ${
                                    page === currentPage
                                        ? 'btn-primary'
                                        : page === '...'
                                        ? 'btn-ghost cursor-default'
                                        : 'btn-ghost'
                                }`}
                                onClick={() => handlePageClick(page)}
                                disabled={page === '...'}
                            >
                                {page}
                            </button>
                        ))}
                    </div>

                    {/* Next page button */}
                    <button
                        className="btn btn-ghost btn-sm"
                        onClick={() => onPageChange(currentPage + 1)}
                        disabled={currentPage === totalPages}
                        title="Next page"
                    >
                        <ChevronRight className="w-4 h-4" />
                    </button>

                    {/* Last page button */}
                    <button
                        className="btn btn-ghost btn-sm"
                        onClick={() => onPageChange(totalPages)}
                        disabled={currentPage === totalPages}
                        title="Last page"
                    >
                        <ChevronsRight className="w-4 h-4" />
                    </button>
                </div>
            )}
        </div>
    );
}